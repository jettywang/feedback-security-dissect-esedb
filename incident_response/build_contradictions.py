"""Build read-only *copies* of a clean ESE fixture that contain state
contradictions typical of an unclean shutdown or a carved/merged database.

Hard guarantees:

* the source fixture is only ever read;
* every mutation is applied to an independent copy under ``samples/``;
* no copy has its ``dbstate`` flipped to clean to disguise damage;
* no transaction log is synthesized and no replay is performed.

Each scenario below models a different evidentiary situation and is described
in the generated manifest so the report reviewer knows exactly which bytes
were changed.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import struct

from dissect.esedb.c_esedb import c_esedb

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
DBSTATE_DIRTY = 2  # JET_dbstateDirtyShutdown


def load_fixture(relative_gz: str) -> bytes:
    with gzip.open(os.path.join(HERE, "..", "tests", "_data", relative_gz), "rb") as fh:
        return fh.read()


def sha256(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def write_sample(name: str, buf: bytes) -> str:
    path = os.path.join(SAMPLES, name)
    with open(path, "wb") as fh:
        fh.write(buf)
    return path


def patch_dword(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value)


def patch_qword(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<q", buf, offset, value)


def fix_legacy_header_checksum(buf: bytearray, page_size: int) -> None:
    """Recompute the legacy XOR checksum of the header page after editing it."""
    digest = 0x89ABCDEF
    rest = bytes(buf[4:page_size])
    for word in struct.unpack(f"<{len(rest) // 4}I", rest):
        digest ^= word
    patch_dword(buf, 0, digest)


def fix_page_xor_checksum(buf: bytearray, page_size: int, logical_pgno: int) -> None:
    """Recompute the XOR half of a modern XECHECKSUM after editing a page.

    The rotating ECC half is intentionally left stale: this mirrors real
    corruption, where a single byte change invalidates both halves and an
    analyst cannot silently regenerate engine-only metadata.
    """
    physical = (logical_pgno + 1) * page_size
    digest = logical_pgno
    for word in struct.unpack(
        f"<{(page_size - 8) // 4}I", bytes(buf[physical + 8 : physical + page_size])
    ):
        digest ^= word
    patch_dword(buf, physical, digest & 0xFFFFFFFF)


def header_offsets(page_size: int) -> dict:
    base = {field.name: field.offset for field in c_esedb.DBFILEHDR.__fields__}
    return base


def build_all(source_gz: str = "basic.edb.gz") -> dict:
    os.makedirs(SAMPLES, exist_ok=True)
    pristine = load_fixture(source_gz)
    hdr = c_esedb.DBFILEHDR(io.BytesIO(pristine))
    page_size = hdr.cbPageSize or 4096
    offsets = header_offsets(page_size)
    manifest = {
        "source_fixture": f"tests/_data/{source_gz}",
        "source_sha256": sha256(pristine),
        "page_size": page_size,
        "scenarios": [],
    }

    def record(name: str, path: str, description: str, mutations: list[dict], new_hash: str) -> None:
        manifest["scenarios"].append(
            {
                "sample": name,
                "path": path,
                "description": description,
                "mutations": mutations,
                "sha256": new_hash,
            }
        )

    # Scenario 0: pristine, untouched reference copy.
    path = write_sample("basic.pristine.edb", pristine)
    record(
        "basic.pristine.edb",
        path,
        "Untouched clean-shutdown fixture used as the control sample.",
        [],
        sha256(pristine),
    )

    # Scenario 1: dirty shutdown, primary header only.
    buf = bytearray(pristine)
    patch_dword(buf, offsets["dbstate"], DBSTATE_DIRTY)
    patch_qword(buf, offsets["dbtimeDirtied"], hdr.dbtimeDirtied + 40)
    # Null out the consistent LGPOS (isec/lGeneration/ib at offset 56) and the
    # companion consistent LOGTIME (8 bytes at offset 64), as a real dirty
    # shutdown header does not carry a valid consistency point.
    struct.pack_into("<IHI", buf, offsets["lgposConsistent"], 0, 0, 0)
    buf[offsets["logtimeConsistent"] : offsets["logtimeConsistent"] + 8] = b"\x00" * 8
    fix_legacy_header_checksum(buf, page_size)
    path = write_sample("dirty-shutdown.edb", bytes(buf))
    record(
        "dirty-shutdown.edb",
        path,
        "Primary header rewritten to dirty shutdown with a newer dbtime and a null lgposConsistent; shadow header stays clean, producing a primary/shadow contradiction.",
        [
            {"offset": offsets["dbstate"], "field": "dbstate", "new_value": DBSTATE_DIRTY},
            {"offset": offsets["dbtimeDirtied"], "field": "dbtimeDirtied", "delta": 40},
            {"offset": offsets["lgposConsistent"], "field": "lgposConsistent", "new_value": "null"},
            {"offset": offsets["logtimeConsistent"], "field": "logtimeConsistent", "new_value": "null"},
        ],
        sha256(bytes(buf)),
    )

    # Scenario 2: a leaf page from a later (fabricated) point in time.
    buf = bytearray(pristine)
    # basic table leaf pages are 13/14; bump dbtime on logical page 14.
    target_logical = 14
    physical = (target_logical + 1) * page_size
    dbtime_offset = physical + 8  # PGHDR: checksum(8) then dbtimeDirtied
    patch_qword(buf, dbtime_offset, hdr.dbtimeDirtied + 25)
    fix_page_xor_checksum(buf, page_size, target_logical)
    # Also mark the primary header dirty so the timeline conflict is explicit.
    patch_dword(buf, offsets["dbstate"], DBSTATE_DIRTY)
    fix_legacy_header_checksum(buf, page_size)
    path = write_sample("mixed-time-page.edb", bytes(buf))
    record(
        "mixed-time-page.edb",
        path,
        "Logical page 14 carries a dbtimeDirtied newer than the database header, modelling a page merged from a later flush; its XOR checksum is regenerated but the ECC half is deliberately stale.",
        [
            {"logical_pgno": target_logical, "field": "dbtimeDirtied", "delta": 25},
            {"field": "dbstate", "new_value": DBSTATE_DIRTY},
        ],
        sha256(bytes(buf)),
    )

    # Scenario 3: catalog references a table root that no longer exists.
    buf = bytearray(pristine)
    # The user table "basic" has root page 31. Zero that page to simulate a
    # missing/damaged directory target without editing the catalog row itself.
    missing_root = 31
    physical = (missing_root + 1) * page_size
    buf[physical : physical + page_size] = b"\x00" * page_size
    patch_dword(buf, offsets["dbstate"], DBSTATE_DIRTY)
    fix_legacy_header_checksum(buf, page_size)
    path = write_sample("missing-catalog-target.edb", bytes(buf))
    record(
        "missing-catalog-target.edb",
        path,
        "Root page 31 referenced by the catalog row for table 'basic' is zeroed, modelling a missing directory target; the catalog claim and the page reality disagree.",
        [
            {"logical_pgno": missing_root, "field": "whole-page", "new_value": "zeroed"},
            {"field": "dbstate", "new_value": DBSTATE_DIRTY},
        ],
        sha256(bytes(buf)),
    )

    # Scenario 4: broken B-tree sibling link on a leaf page.
    buf = bytearray(pristine)
    broken_logical = 13  # leaf 13 currently points next -> 14
    physical = (broken_logical + 1) * page_size
    # PGHDR layout: checksum(8) dbtime(8) pgnoPrev(4) pgnoNext(4)
    pgno_next_offset = physical + 8 + 8 + 4
    patch_dword(buf, pgno_next_offset, 999)  # points outside the file
    fix_page_xor_checksum(buf, page_size, broken_logical)
    patch_dword(buf, offsets["dbstate"], DBSTATE_DIRTY)
    fix_legacy_header_checksum(buf, page_size)
    path = write_sample("broken-btree-link.edb", bytes(buf))
    record(
        "broken-btree-link.edb",
        path,
        "Leaf page 13 has pgnoNext rewritten to an out-of-range page number; ordered leaf traversal is unreliable even though individual pages still parse.",
        [
            {"logical_pgno": broken_logical, "field": "pgnoNext", "new_value": 999},
            {"field": "dbstate", "new_value": DBSTATE_DIRTY},
        ],
        sha256(bytes(buf)),
    )

    # Scenario 5: silent byte tampering inside a data page (checksum not fixed).
    buf = bytearray(pristine)
    tampered_logical = 14
    physical = (tampered_logical + 1) * page_size
    # Flip bytes inside the record area, well past the 40-byte page header.
    tamper_offset = physical + 200
    buf[tamper_offset] ^= 0xA5
    buf[tamper_offset + 1] ^= 0x5A
    path = write_sample("tampered-page.edb", bytes(buf))
    record(
        "tampered-page.edb",
        path,
        "Two bytes inside logical page 14 are flipped without touching the checksum, modelling post-flash tampering; the header still claims clean shutdown to show why the header flag alone is not proof.",
        [
            {"logical_pgno": tampered_logical, "file_offset": tamper_offset, "field": "data-bytes"},
        ],
        sha256(bytes(buf)),
    )

    manifest_path = os.path.join(HERE, "samples_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


if __name__ == "__main__":
    result = build_all()
    print(json.dumps(result, indent=2))
