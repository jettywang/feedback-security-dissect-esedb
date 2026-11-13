"""Read-only forensic triage for ESE (Extensible Storage Engine) databases.

This module deliberately performs *observation only*:

* it never writes to the evidence file (the handle is opened in ``rb`` mode);
* it never flips ``dbstate`` or any page flag to make a dirty database look
  clean;
* it never attempts transaction replay, because replay requires the matching
  transaction logs (``.log`` / ``.jrs`` / ``.chk``), which are absent here.

The output separates two claims that are easy to conflate:

1. **Structurally parseable** - bytes can be decoded into headers, pages and
   B-tree nodes.  A record that parses is evidence that the bytes existed on
   disk, not that a transaction committed.
2. **Transactionally committed** - only the ESE engine, replaying the write
   ahead logs against a consistent checkpoint, can establish this.  Without the
   logs the analyst must report commit state as *indeterminate*.

The checksum strategy is conservative: the XOR half of the modern
``XECHECKSUM`` is fully reproduced (it folds the logical page number into the
checksum slot); the rotating ECC half is reported but not independently
re-derived, matching the documented "engine-validated" status of that field.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import io
import json
import os
import struct
from typing import BinaryIO

from dissect.esedb.c_esedb import PAGE_FLAG, c_esedb, ulDAEMagic
from dissect.esedb.exceptions import InvalidDatabase
from dissect.esedb.page import Page

# JET_dbstate values (see Microsoft ESE headers, jet.h).
DBSTATE = {
    1: "JET_dbstateJustCreated",
    2: "JET_dbstateDirtyShutdown",
    3: "JET_dbstateCleanShutdown",
    4: "JET_dbstateBeingConverted",
    5: "JET_dbstateForceDetach",
    6: "JET_dbstateRecoveryOnNewLog",
}

# Finding severity, from most to least severe.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Structural parse result labels.
PARSE_OK = "parseable"
PARSE_DEGRADED = "parseable-with-errors"
PARSE_FAILED = "unparseable"

# Commit-state labels.  Everything derived without logs defaults to UNKNOWN.
COMMIT_UNKNOWN = "indeterminate-without-logs"
COMMIT_CLEAN_HEADER = "header-asserts-clean-shutdown"

XOR_SEED = 0x89ABCDEF


@dataclasses.dataclass
class Finding:
    severity: str
    code: str
    message: str
    detail: dict = dataclasses.field(default_factory=dict)

    def as_dict(self) -> dict:
        out = dataclasses.asdict(self)
        return out


def decode_logtime(lt) -> str | None:
    """Decode an ESE LOGTIME into an ISO-like UTC string, or ``None`` when empty."""
    if lt is None:
        return None
    if all(
        getattr(lt, name, 0) == 0
        for name in ("bYear", "bMonth", "bDay", "bHours", "bMinutes", "bSeconds")
    ):
        return None
    millis = (lt.bMillisecondsHigh << 7) | lt.bMillisecondsLow
    try:
        when = dt.datetime(
            1900 + lt.bYear,
            max(lt.bMonth, 1),
            max(lt.bDay, 1),
            lt.bHours,
            lt.bMinutes,
            lt.bSeconds,
        )
    except ValueError:
        return None
    return when.strftime("%Y-%m-%d %H:%M:%S") + f".{millis:03d}"


def xor_checksum_old_format(buf: bytes) -> int:
    """Legacy header checksum: XOR of every DWORD after the checksum slot."""
    digest = XOR_SEED
    for word in struct.unpack(f"<{len(buf) // 4}I", buf):
        digest ^= word
    return digest


def page_xor_checksum(page_buf: bytes, logical_pgno: int) -> int:
    """Reproduce the XOR half of a modern XECHECKSUM for a small (<= 8K) page.

    The engine treats the 8-byte checksum slot as ``(logical page number, 0)``
    while computing the running XOR, i.e. the checksum is bound to the page
    number so a relocated page cannot keep a valid checksum.
    """
    digest = logical_pgno
    for word in struct.unpack(f"<{(len(page_buf) - 8) // 4}I", page_buf[8:]):
        digest ^= word
    return digest & 0xFFFFFFFF


def first_block_xor_checksum(page_buf: bytes, logical_pgno: int) -> int:
    """Reproduce the header-block XOR half of a large-page XECHECKSUM.

    Large pages keep a checksum per 4 K block.  The block-0 checksum stored in
    ``PGHDR`` is fully reproducible; the rotating block checksums in
    ``PGHDR2.rgChecksum`` are engine-managed and are not re-derived here.  This
    function therefore validates only the first block, which is reported
    explicitly rather than presented as whole-page coverage.
    """
    block = bytearray(page_buf[:4096])
    block[0:4] = struct.pack("<I", logical_pgno)
    block[4:8] = b"\x00" * 4
    digest = 0
    for word in struct.unpack(f"<{len(block) // 4}I", bytes(block)):
        digest ^= word
    return digest & 0xFFFFFFFF


class ReadOnlyEseFile:
    """Raw, defensive access to the on-disk file, independent of the parser."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.size = os.path.getsize(self.path)
        # Explicit read-only binary handle.  Nothing in this class ever seeks
        # for the purpose of writing.
        self.fh: BinaryIO = open(self.path, "rb")
        self._peek = self.fh.read(len(c_esedb.DBFILEHDR))
        self.fh.seek(0)
        self.header = c_esedb.DBFILEHDR(io.BytesIO(self._peek))
        self.page_size = self.header.cbPageSize or 4096
        self.physical_pages = self.size // self.page_size
        # Logical pages start at physical page 2 (header + shadow header).
        self.logical_pages = max(self.physical_pages - 2, 0)

    def close(self) -> None:
        self.fh.close()

    def read_physical(self, index: int) -> bytes:
        self.fh.seek(index * self.page_size)
        buf = self.fh.read(self.page_size)
        if len(buf) != self.page_size:
            raise IndexError(f"short read at physical page {index}")
        return buf

    def header_bytes(self) -> bytes:
        return self._peek


class ForensicAnalyzer:
    """Run all read-only checks and collect graded findings."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.raw = ReadOnlyEseFile(path)
        self.findings: list[Finding] = []
        self.header_facts: dict = {}
        self.page_facts: list[dict] = []
        self.btree_facts: dict = {}
        self.db = None
        self.parse_state = PARSE_OK

    # -- helpers -----------------------------------------------------------

    def add(self, severity: str, code: str, message: str, **detail) -> None:
        self.findings.append(Finding(severity, code, message, detail))

    @staticmethod
    def _lgpos_dict(lgpos) -> dict:
        if lgpos is None:
            return {}
        return {"ib": lgpos.ib, "isec": lgpos.isec, "generation": lgpos.lGeneration}

    @staticmethod
    def _lgpos_is_null(lgpos) -> bool:
        return lgpos is None or (lgpos.ib == 0 and lgpos.isec == 0 and lgpos.lGeneration == 0)

    # -- header level ------------------------------------------------------

    def analyze_headers(self) -> None:
        primary = self.raw.header
        page_size = self.raw.page_size
        shadow = c_esedb.DBFILEHDR(io.BytesIO(self.raw.read_physical(1)))

        if primary.ulMagic != ulDAEMagic:
            self.add(
                "CRITICAL",
                "HDR_MAGIC",
                "Primary header magic does not match an ESE database; file may not be an ESE DB.",
                magic=hex(primary.ulMagic),
                expected=hex(ulDAEMagic),
            )

        # Legacy 4 KB header checksum, fully reproducible.
        header_page = bytearray(self.raw.read_physical(0))
        stored_header_checksum = struct.unpack("<I", header_page[:4])[0]
        calc_header_checksum = xor_checksum_old_format(bytes(header_page[4:]))
        header_checksum_ok = stored_header_checksum == calc_header_checksum
        if not header_checksum_ok:
            self.add(
                "HIGH",
                "HDR_CHECKSUM",
                "Database header page checksum does not match; header bytes may be altered.",
                stored=hex(stored_header_checksum),
                calculated=hex(calc_header_checksum),
            )

        state_name = DBSTATE.get(primary.dbstate, f"unknown({primary.dbstate})")
        self.header_facts = {
            "file": self.path,
            "file_size": self.raw.size,
            "page_size": page_size,
            "physical_pages": self.raw.physical_pages,
            "logical_pages": self.raw.logical_pages,
            "ulVersion": primary.ulVersion,
            "format_major": primary.ulDaeUpdateMajor,
            "format_minor": primary.ulDaeUpdateMinor,
            "dbstate": primary.dbstate,
            "dbstate_name": state_name,
            "dbtimeDirtied": primary.dbtimeDirtied,
            "header_checksum_ok": header_checksum_ok,
            "logtimeAttach": decode_logtime(primary.logtimeAttach),
            "logtimeDetach": decode_logtime(primary.logtimeDetach),
            "logtimeConsistent": decode_logtime(primary.logtimeConsistent),
            "lgposConsistent": self._lgpos_dict(primary.lgposConsistent),
            "lgposConsistent_null": self._lgpos_is_null(primary.lgposConsistent),
            "lgposAttach": self._lgpos_dict(primary.lgposAttach),
            "lgposDetach": self._lgpos_dict(primary.lgposDetach),
            "lGenMinRequired": primary.lGenMinRequired,
            "lGenMaxRequired": primary.lGenMaxRequired,
            "lGenMinConsistent": primary.lGenMinConsistent,
            "lGenMaxCommitted": primary.lGenMaxCommitted,
            "signDb_ulRandom": hex(primary.signDb.ulRandom),
            "signLog_ulRandom": hex(primary.signLog.ulRandom),
            "logtimeCreate": decode_logtime(primary.signDb.logtimeCreate),
            "computer": bytes(primary.signDb.szComputerName).rstrip(b"\x00").decode(
                "latin-1", errors="replace"
            ),
        }

        if primary.dbstate != 3:
            self.add(
                "HIGH",
                "HDR_DIRTY",
                f"dbstate is {state_name}, not clean shutdown; committed state cannot be asserted without logs.",
                dbstate=primary.dbstate,
                lgposConsistent_null=self._lgpos_is_null(primary.lgposConsistent),
            )
        else:
            self.add(
                "INFO",
                "HDR_CLEAN",
                "dbstate asserts clean shutdown. This is a header claim; verify it against page and checksum evidence.",
            )

        if self._lgpos_is_null(primary.lgposConsistent):
            self.add(
                "MEDIUM",
                "HDR_NO_CONSISTENT_LGPOS",
                "lgposConsistent is null; no on-disk pointer to a consistent log position.",
            )

        # Shadow (backup) header comparison.
        shadow_state = DBSTATE.get(shadow.dbstate, f"unknown({shadow.dbstate})")
        compared = (
            "ulMagic",
            "dbstate",
            "dbtimeDirtied",
            "cbPageSize",
            "ulVersion",
            "objidLast",
        )
        mismatches = []
        for attr in compared:
            if getattr(primary, attr) != getattr(shadow, attr):
                mismatches.append(
                    {
                        "field": attr,
                        "primary": getattr(primary, attr),
                        "shadow": getattr(shadow, attr),
                    }
                )
        if primary.signDb.ulRandom != shadow.signDb.ulRandom:
            mismatches.append(
                {
                    "field": "signDb.ulRandom",
                    "primary": hex(primary.signDb.ulRandom),
                    "shadow": hex(shadow.signDb.ulRandom),
                }
            )
        self.header_facts["shadow_dbstate"] = shadow.dbstate
        self.header_facts["shadow_dbstate_name"] = shadow_state
        self.header_facts["shadow_dbtimeDirtied"] = shadow.dbtimeDirtied
        self.header_facts["shadow_signDb_ulRandom"] = hex(shadow.signDb.ulRandom)
        self.header_facts["shadow_mismatches"] = mismatches
        if shadow.ulMagic != ulDAEMagic:
            self.add(
                "HIGH",
                "SHADOW_MAGIC",
                "Shadow header has an invalid magic; the backup header is unusable.",
                magic=hex(shadow.ulMagic),
            )
        if mismatches:
            self.add(
                "HIGH",
                "SHADOW_DIVERGENCE",
                "Primary and shadow headers disagree; the file mixes at least two header flush points.",
                mismatches=mismatches,
            )
        else:
            self.add("INFO", "SHADOW_MATCH", "Primary and shadow headers are consistent.")

    # -- page level --------------------------------------------------------

    def _safe_page(self, logical_pgno: int, buf: bytes) -> Page | None:
        try:
            return Page(self.db, logical_pgno, buf)
        except Exception as exc:  # parser raised: record the structural failure
            self.add(
                "HIGH",
                "PAGE_PARSE",
                f"Logical page {logical_pgno} could not be parsed by dissect.esedb.",
                logical_pgno=logical_pgno,
                error=repr(exc),
            )
            self.parse_state = PARSE_DEGRADED
            return None

    def analyze_pages(self) -> None:
        dbtimes: list[int] = []
        bad_checksum = 0
        new_checksum_pages = 0
        old_checksum_pages = 0
        partial_checksum_pages = 0
        zero_pages = 0
        parse_failures = 0
        out_of_bounds_links: list[dict] = []
        flag_breakdown: dict[str, int] = {}
        large_page = self.raw.page_size > 8192

        for logical_pgno in range(1, self.raw.logical_pages + 1):
            buf = self.raw.read_physical(logical_pgno + 1)
            is_zero = all(b == 0 for b in buf)
            page = self._safe_page(logical_pgno, buf)
            if page is None:
                parse_failures += 1
                self.page_facts.append(
                    {"logical_pgno": logical_pgno, "status": "unparseable", "zero": is_zero}
                )
                continue

            flags = int(page.flags)
            for name, member in PAGE_FLAG.__members__.items():
                if member.value and flags & member.value:
                    flag_breakdown[name] = flag_breakdown.get(name, 0) + 1

            fact = {
                "logical_pgno": logical_pgno,
                "physical_pgno": logical_pgno + 2,
                "zero": is_zero,
                "flags": hex(flags),
                "flags_int": flags,
                "dbtimeDirtied": page.header.dbtimeDirtied,
                "pgnoPrev": page.previous_page,
                "pgnoNext": page.next_page,
                "objidFDP": page.header.objidFDP,
                "node_count": page.node_count,
                "is_leaf": page.is_leaf,
                "is_root": page.is_root,
            }

            if is_zero:
                zero_pages += 1
                fact["checksum"] = "n/a-zero-page"
                self.page_facts.append(fact)
                continue

            dbtimes.append(page.header.dbtimeDirtied)
            uses_new = bool(flags & PAGE_FLAG.NewChecksumFormat)
            fact["new_checksum_format"] = uses_new
            checksum_ok = None
            if uses_new:
                new_checksum_pages += 1
                ecc_half, xor_half = struct.unpack("<II", buf[:8])
                if large_page:
                    # Large pages use a rotating, multi-block checksum whose
                    # full re-derivation is engine-internal (per-block values
                    # are stored in PGHDR2.rgChecksum).  Empirically the simple
                    # DWORD XOR only reproduces a subset of large pages, so it is
                    # never treated as proof of corruption here.  Large-page
                    # integrity is reported as engine-validated-only.
                    partial_checksum_pages += 1
                    calculated = first_block_xor_checksum(buf, logical_pgno)
                    fact["checksum"] = {
                        "format": "XECHECKSUM-large-page",
                        "coverage": "engine-validated-only (multi-block rotating checksum not independently re-derived)",
                        "stored_xor_half": hex(ecc_half),
                        "stored_ecc_half": hex(xor_half),
                        "candidate_first_block_xor": hex(calculated),
                        "first_block_candidate_matches": calculated == ecc_half,
                        "verdict": "not-independently-verifiable-without-engine",
                    }
                    # Intentionally do not set checksum_ok: a mismatch is not
                    # evidence of tampering for large pages.
                else:
                    calculated = page_xor_checksum(buf, logical_pgno)
                    checksum_ok = calculated == ecc_half
                    fact["checksum"] = {
                        "format": "XECHECKSUM",
                        "coverage": "whole-page",
                        "stored_xor_half": hex(ecc_half),
                        "stored_ecc_half": hex(xor_half),
                        "calculated_xor": hex(calculated),
                        "xor_half_ok": checksum_ok,
                        "ecc_half": "engine-validated-only",
                    }
            else:
                old_checksum_pages += 1
                stored = struct.unpack("<I", buf[:4])[0]
                calculated = xor_checksum_old_format(buf[4:])
                checksum_ok = stored == calculated
                fact["checksum"] = {
                    "format": "legacy-XOR",
                    "coverage": "whole-page",
                    "stored": hex(stored),
                    "calculated": hex(calculated),
                    "ok": checksum_ok,
                }

            if checksum_ok is False:
                bad_checksum += 1
                scope = "first 4K block of a large page" if large_page else "whole page"
                self.add(
                    "HIGH",
                    "PAGE_CHECKSUM",
                    f"Logical page {logical_pgno} fails the reproducible XOR checksum ({scope}); bytes changed after flush or page moved.",
                    logical_pgno=logical_pgno,
                    physical_pgno=logical_pgno + 2,
                    coverage=fact["checksum"]["coverage"],
                )

            for label, target in (("pgnoPrev", page.previous_page), ("pgnoNext", page.next_page)):
                if target and not (1 <= target <= self.raw.logical_pages):
                    out_of_bounds_links.append(
                        {"logical_pgno": logical_pgno, "field": label, "target": target}
                    )
            self.page_facts.append(fact)

        if out_of_bounds_links:
            self.add(
                "HIGH",
                "BTREE_LINK_OOB",
                "One or more sibling page links point outside the file.",
                links=out_of_bounds_links,
            )
        if partial_checksum_pages:
            self.add(
                "INFO",
                "LARGE_PAGE_CHECKSUM_SCOPE",
                "Database uses large pages; their rotating multi-block XECHECKSUM (PGHDR2.rgChecksum) is not independently re-derived, so large-page integrity requires engine validation. Small-page XOR checksums remain fully verified.",
                large_pages=partial_checksum_pages,
            )

        # Page-time coherence: pages from different flush points in one file.
        # The ESE header dbtime is a database-wide counter snapshot; page
        # dbtimes legitimately trail it.  A page that is *strictly newer* than
        # the header while the header already declares dirty shutdown is the
        # strong indicator that pages from different points in time were
        # merged, so only flag that combination.
        distinct_dbtimes = sorted(set(dbtimes))
        header_dbtime = self.raw.header.dbtimeDirtied
        header_declares_dirty = self.raw.header.dbstate != 3
        future_pages = [
            f["logical_pgno"]
            for f in self.page_facts
            if not f.get("zero") and f.get("dbtimeDirtied", 0) > header_dbtime
        ]
        self.btree_facts["page_time"] = {
            "distinct_dbtimeDirtied": distinct_dbtimes,
            "header_dbtimeDirtied": header_dbtime,
            "pages_newer_than_header": future_pages,
            "min_page_dbtime": distinct_dbtimes[0] if distinct_dbtimes else None,
            "max_page_dbtime": distinct_dbtimes[-1] if distinct_dbtimes else None,
        }
        if future_pages and header_declares_dirty:
            self.add(
                "CRITICAL",
                "PAGE_TIME_FUTURE",
                "Dirty header coexists with pages whose dbtimeDirtied is newer than the header; the file is assembled from different points in time.",
                pages=future_pages,
                header_dbtime=header_dbtime,
            )
        elif future_pages:
            self.add(
                "HIGH",
                "PAGE_TIME_FUTURE",
                "Pages carry a dbtimeDirtied newer than a header that still claims clean shutdown; the clean flag is contradicted by page time evidence.",
                pages=future_pages,
                header_dbtime=header_dbtime,
            )
        if len(distinct_dbtimes) > 1:
            self.add(
                "INFO",
                "PAGE_TIME_SPREAD",
                "Pages span multiple dbtime values; this is normal for a live DB but proves mixed flush points.",
                distinct_values=len(distinct_dbtimes),
                min=distinct_dbtimes[0],
                max=distinct_dbtimes[-1],
            )

        self.btree_facts["page_counts"] = {
            "logical_pages": self.raw.logical_pages,
            "zero_pages": zero_pages,
            "new_checksum_pages": new_checksum_pages,
            "legacy_checksum_pages": old_checksum_pages,
            "large_page_first_block_only_checksums": partial_checksum_pages,
            "bad_reproducible_checksum": bad_checksum,
            "parse_failures": parse_failures,
        }
        self.btree_facts["flag_breakdown"] = flag_breakdown

    # -- B-tree / catalog level -------------------------------------------

    def _walk_branch_tree(self, root_pgno: int, seen: set) -> tuple[set, list[dict]]:
        """Return (reachable pages, structural errors) via branch references."""
        errors: list[dict] = []
        if root_pgno in seen:
            errors.append({"code": "cycle", "page": root_pgno})
            return set(), errors
        seen.add(root_pgno)
        try:
            page = self.db.page(root_pgno)
        except Exception as exc:
            errors.append({"code": "unreachable-page", "page": root_pgno, "error": repr(exc)})
            return {root_pgno}, errors

        reachable = {root_pgno}
        if page.is_leaf:
            return reachable, errors

        for node in page.nodes():
            child = node.child
            if not (1 <= child <= self.raw.logical_pages):
                errors.append(
                    {"code": "child-out-of-bounds", "parent": root_pgno, "child": child}
                )
                continue
            sub, sub_err = self._walk_branch_tree(child, seen)
            reachable |= sub
            errors.extend(sub_err)
        return reachable, errors

    def analyze_btree(self) -> None:
        # Catalog root is logical page pgnoFDPMSO (4) per the ESE format.
        catalog_pgno = 4
        catalog_reachable, catalog_errors = self._walk_branch_tree(catalog_pgno, set())
        if catalog_errors:
            self.parse_state = PARSE_DEGRADED
            self.add(
                "HIGH",
                "CATALOG_TREE",
                "Catalog B-tree has structural errors; some catalog entries may be missing.",
                errors=catalog_errors,
            )

        tables = []
        catalog_parse_error = None
        try:
            tables = self.db.tables()
        except Exception as exc:
            catalog_parse_error = repr(exc)
            self.add(
                "CRITICAL",
                "CATALOG_PARSE",
                "Catalog could not be enumerated; table-level references cannot be trusted.",
                error=catalog_parse_error,
            )
            self.parse_state = PARSE_DEGRADED

        table_info = []
        all_tree_pages: set[int] = set()
        long_value_pages: set[int] = set()
        leaf_chain_errors: list[dict] = []
        for table in tables:
            root = table.root_page
            reachable, errors = self._walk_branch_tree(root, set())
            all_tree_pages |= reachable
            for err in errors:
                err["table"] = table.name
            if errors:
                leaf_chain_errors.extend(errors)

            # Long-value (separated LV / SLV) data lives in its own B-tree,
            # reachable from the catalog LongValue row rather than the table
            # root, so it must be walked separately to avoid false orphans.
            lv_root = None
            if table._long_value_record is not None:
                lv_root = table._long_value_record.get("ColtypOrPgnoFDP")
                if isinstance(lv_root, int) and 1 <= lv_root <= self.raw.logical_pages:
                    lv_reachable, lv_errors = self._walk_branch_tree(lv_root, set())
                    long_value_pages |= lv_reachable
                    for err in lv_errors:
                        err["table"] = table.name
                        err["tree"] = "long-value"
                    leaf_chain_errors.extend(lv_errors)

            # Secondary indexes have their own B-tree roots recorded in the
            # catalog; walk them so index pages are not mistaken for orphans.
            index_roots = []
            for index in table.indexes:
                try:
                    index_root = index.record.get("ColtypOrPgnoFDP")
                except Exception:
                    index_root = None
                if not isinstance(index_root, int) or not (1 <= index_root <= self.raw.logical_pages):
                    continue
                if index_root == root:
                    continue  # primary index shares the table root
                index_roots.append(index_root)
                ix_reachable, ix_errors = self._walk_branch_tree(index_root, set())
                all_tree_pages |= ix_reachable
                for err in ix_errors:
                    err["table"] = table.name
                    err["tree"] = f"index:{index.name}"
                leaf_chain_errors.extend(ix_errors)

            table_info.append(
                {
                    "name": table.name,
                    "root_page": root,
                    "long_value_root": lv_root,
                    "secondary_index_roots": index_roots,
                    "reachable_pages": sorted(reachable),
                    "columns": len(table.columns),
                    "indices": len(table.indexes),
                }
            )

            # Sibling chain integrity on leaf pages: prev/next must be mutual.
            for pgno in reachable:
                page = self.db.page(pgno)
                if not page.is_leaf:
                    continue
                if page.next_page:
                    if not (1 <= page.next_page <= self.raw.logical_pages):
                        leaf_chain_errors.append(
                            {
                                "table": table.name,
                                "code": "next-out-of-bounds",
                                "page": pgno,
                                "target": page.next_page,
                            }
                        )
                        continue
                    nxt = self.db.page(page.next_page)
                    if nxt.previous_page != pgno:
                        leaf_chain_errors.append(
                            {
                                "table": table.name,
                                "code": "non-reciprocal-next",
                                "page": pgno,
                                "next": page.next_page,
                                "next_prev": nxt.previous_page,
                            }
                        )
                if page.previous_page:
                    if not (1 <= page.previous_page <= self.raw.logical_pages):
                        leaf_chain_errors.append(
                            {
                                "table": table.name,
                                "code": "prev-out-of-bounds",
                                "page": pgno,
                                "target": page.previous_page,
                            }
                        )
                        continue
                    prv = self.db.page(page.previous_page)
                    if prv.next_page != pgno:
                        leaf_chain_errors.append(
                            {
                                "table": table.name,
                                "code": "non-reciprocal-prev",
                                "page": pgno,
                                "prev": page.previous_page,
                                "prev_next": prv.next_page,
                            }
                        )

        if leaf_chain_errors:
            self.parse_state = PARSE_DEGRADED
            self.add(
                "HIGH",
                "BTREE_LINK",
                "B-tree branch or leaf sibling links are broken; ordered traversal is not reliable.",
                errors=leaf_chain_errors[:25],
                total_errors=len(leaf_chain_errors),
            )

        # Directory (catalog) reference coverage.  Space-tree pages, the
        # catalog name/root indexes and empty pages are structural metadata
        # rather than user data and must not be reported as orphans.
        referenced_roots = {t.root_page for t in tables}
        physical_nonzero = {
            f["logical_pgno"] for f in self.page_facts if not f.get("zero") and "flags" in f
        }
        referenced_pages = set()
        for info in table_info:
            referenced_pages |= set(info["reachable_pages"])
        # The catalog tree and its two auxiliary indexes (name index root 7
        # and root-object index root 10) are metadata, not orphans even though
        # no table row references them.
        metadata_pages = set(catalog_reachable)
        for auxiliary_root in (7, 10):
            if 1 <= auxiliary_root <= self.raw.logical_pages:
                aux_reachable, aux_errors = self._walk_branch_tree(auxiliary_root, set())
                metadata_pages |= aux_reachable
                catalog_errors.extend(aux_errors)
        structural_pages = {
            f["logical_pgno"]
            for f in self.page_facts
            if "flags_int" in f
            and (
                f.get("is_root")
                or f["flags_int"] & PAGE_FLAG.SpaceTree
                or f.get("node_count", 0) == 0
                # Freed / garbage pages do not carry the record-format bit.
                # They are surfaced by checksum or parse findings, not as
                # directory orphans, to keep orphan semantics precise.
                or not (f["flags_int"] & PAGE_FLAG.NewRecordFormat)
            )
        }
        orphan_pages = sorted(
            physical_nonzero
            - referenced_pages
            - all_tree_pages
            - long_value_pages
            - metadata_pages
            - structural_pages
        )
        missing_roots = sorted(r for r in referenced_roots if r not in physical_nonzero)
        if missing_roots:
            self.add(
                "CRITICAL",
                "CATALOG_DANGLING_ROOT",
                "Catalog references table root pages that do not exist as allocated pages.",
                roots=missing_roots,
            )
        if orphan_pages:
            self.add(
                "MEDIUM",
                "CATALOG_ORPHAN_PAGE",
                "Allocated, well-formed pages are not reachable from any catalog table, index or long-value tree; they may hold stale, freed or redirected data and can still be carved as evidence even though no directory row names them.",
                pages=orphan_pages,
            )

        self.btree_facts["tables"] = table_info
        self.btree_facts["catalog"] = {
            "root_page": catalog_pgno,
            "reachable_pages": sorted(catalog_reachable),
            "parse_error": catalog_parse_error,
        }
        self.btree_facts["coverage"] = {
            "allocated_nonzero_pages": sorted(physical_nonzero),
            "referenced_tree_pages": sorted(
                referenced_pages | all_tree_pages | long_value_pages | metadata_pages
            ),
            "long_value_pages": sorted(long_value_pages),
            "orphan_pages": orphan_pages,
            "missing_roots": missing_roots,
        }

    # -- record evidence ---------------------------------------------------

    def analyze_records(self) -> None:
        """Count records per table without asserting commit state."""
        record_summary = []
        for table in self.db.tables():
            total = 0
            failed = 0
            try:
                for _ in table.records():
                    total += 1
            except Exception as exc:
                failed += 1
                self.add(
                    "MEDIUM",
                    "RECORD_ITERATION",
                    f"Record iteration in table {table.name} aborted; the table is only partially readable.",
                    table=table.name,
                    error=repr(exc),
                )
                self.parse_state = PARSE_DEGRADED
            record_summary.append(
                {"table": table.name, "records_decoded": total, "iteration_errors": failed}
            )
        self.btree_facts["records"] = record_summary

    # -- orchestration -----------------------------------------------------

    def run(self) -> dict:
        self.analyze_headers()
        try:
            from dissect.esedb.esedb import EseDB

            self.db = EseDB(open(self.path, "rb"))
        except InvalidDatabase as exc:
            self.add(
                "CRITICAL",
                "PARSER_REJECT",
                "dissect.esedb refuses the file; only raw header/page facts are available.",
                error=repr(exc),
            )
            self.parse_state = PARSE_FAILED
            return self.report()
        except Exception as exc:
            self.add("CRITICAL", "PARSER_ERROR", "Unexpected parser failure.", error=repr(exc))
            self.parse_state = PARSE_FAILED
            return self.report()

        self.analyze_pages()
        self.analyze_btree()
        self.analyze_records()
        return self.report()

    # Findings that invalidate even a clean-shutdown header claim.  Any of
    # these means the on-disk bytes are not self-consistent, so commit state
    # must stay indeterminate until the transaction logs are available.
    CLEAN_CLAIM_DISQUALIFIERS = {
        "HDR_CHECKSUM",
        "SHADOW_DIVERGENCE",
        "PAGE_TIME_FUTURE",
        "PAGE_CHECKSUM",
        "BTREE_LINK",
        "BTREE_LINK_OOB",
        "CATALOG_DANGLING_ROOT",
        "CATALOG_PARSE",
        "PARSER_REJECT",
        "PARSER_ERROR",
    }

    def report(self) -> dict:
        commit_state = COMMIT_UNKNOWN
        observed = {f.code for f in self.findings}
        if (
            self.header_facts.get("dbstate") == 3
            and not (observed & self.CLEAN_CLAIM_DISQUALIFIERS)
        ):
            commit_state = COMMIT_CLEAN_HEADER
        if self.parse_state == PARSE_FAILED:
            commit_state = COMMIT_UNKNOWN

        counts = {sev: 0 for sev in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1

        return {
            "evidence_file": self.path,
            "mode": "read-only",
            "mutations_performed": [],
            "replay_attempted": False,
            "structural_parse_state": self.parse_state,
            "transaction_commit_state": commit_state,
            "header": self.header_facts,
            "pages": self.btree_facts.get("page_counts", {}),
            "page_time": self.btree_facts.get("page_time", {}),
            "btree": {
                key: self.btree_facts.get(key)
                for key in ("catalog", "tables", "coverage", "flag_breakdown", "records")
                if key in self.btree_facts
            },
            "finding_counts": counts,
            "findings": [f.as_dict() for f in self.findings],
        }


def render_text(report: dict) -> str:
    """Human-readable graded report."""
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("ESE READ-ONLY FORENSIC TRIAGE REPORT")
    lines.append("=" * 78)
    lines.append(f"Evidence file        : {report['evidence_file']}")
    lines.append(f"Access mode          : {report['mode']} (no writes, no flag edits, no replay)")
    lines.append(f"Structural parse     : {report['structural_parse_state']}")
    lines.append(f"Transaction commit   : {report['transaction_commit_state']}")
    lines.append("")

    hdr = report.get("header", {})
    lines.append("-- Header facts")
    for key in (
        "dbstate_name",
        "dbtimeDirtied",
        "page_size",
        "physical_pages",
        "logical_pages",
        "header_checksum_ok",
        "logtimeAttach",
        "logtimeDetach",
        "logtimeConsistent",
        "lgposConsistent_null",
        "lGenMinRequired",
        "lGenMaxRequired",
        "lGenMaxCommitted",
        "signDb_ulRandom",
        "signLog_ulRandom",
        "shadow_dbstate_name",
        "shadow_dbtimeDirtied",
        "shadow_signDb_ulRandom",
        "shadow_mismatches",
    ):
        if key in hdr:
            lines.append(f"  {key:24s}: {hdr[key]}")
    lines.append("")

    pt = report.get("page_time", {})
    if pt:
        lines.append("-- Page time coherence")
        lines.append(f"  header dbtimeDirtied  : {pt.get('header_dbtimeDirtied')}")
        lines.append(f"  page dbtime range     : {pt.get('min_page_dbtime')} .. {pt.get('max_page_dbtime')}")
        lines.append(f"  pages newer than hdr  : {pt.get('pages_newer_than_header')}")
        lines.append("")

    pages = report.get("pages", {})
    if pages:
        lines.append("-- Page inventory")
        for key, value in pages.items():
            lines.append(f"  {key:24s}: {value}")
        lines.append("")

    btree = report.get("btree", {})
    coverage = btree.get("coverage", {})
    if coverage:
        lines.append("-- Catalog / directory coverage")
        lines.append(f"  orphan pages          : {coverage.get('orphan_pages')}")
        lines.append(f"  missing table roots   : {coverage.get('missing_roots')}")
        lines.append("")
    records = btree.get("records", [])
    if records:
        lines.append("-- Decoded record counts (existence of bytes, not proof of commit)")
        for row in records:
            lines.append(
                f"  {row['table']:24s}: {row['records_decoded']} records, "
                f"{row['iteration_errors']} iteration error(s)"
            )
        lines.append("")

    lines.append("-- Graded findings")
    if not report["findings"]:
        lines.append("  (none)")
    for finding in report["findings"]:
        lines.append(f"  [{finding['severity']:8s}] {finding['code']}: {finding['message']}")
        if finding.get("detail"):
            for key, value in finding["detail"].items():
                lines.append(f"               {key}: {value}")
    lines.append("")
    lines.append("Finding counts: " + ", ".join(f"{k}={v}" for k, v in report["finding_counts"].items()))
    return "\n".join(lines)


def analyze_file(path: str) -> dict:
    analyzer = ForensicAnalyzer(path)
    try:
        return analyzer.run()
    finally:
        analyzer.raw.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only ESE forensic triage (no repair, no replay).")
    parser.add_argument("database", help="path to the ESE database file (opened read-only)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--output", help="write the report to this path instead of stdout")
    args = parser.parse_args(argv)

    report = analyze_file(args.database)
    rendered = json.dumps(report, indent=2, default=str) if args.json else render_text(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered + "\n")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
