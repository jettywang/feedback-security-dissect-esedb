#!/usr/bin/env python3
"""Field-level audit of dissect.esedb ``impacket_compat`` mode vs native parsing.

Opens each database twice (read-only), once natively and once with
``impacket_compat=True``, walks the same records, and for every column records:

* the catalog column definition (identifier, declared type, size, encoding, storage class)
* the raw on-disk bytes (``record.get(name, raw=True)``)
* the native parsed value
* the impacket-compat value
* a classification describing how the two differ, and whether information is lost

It then prints a human report and writes a JSON report plus a Markdown field-level
migration table. Databases are only ever opened ``rb``; nothing is written to them.

Usage::

    python audit/ese_compat_audit.py                      # all fixtures under tests/_data
    python audit/ese_compat_audit.py tests/_data/multi.edb.gz
    python audit/ese_compat_audit.py --out audit/report
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
from binascii import hexlify, unhexlify
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from dissect.esedb import EseDB
from dissect.esedb.c_esedb import TAGFLD_HEADER

# ---------------------------------------------------------------------------
# Classifications
# ---------------------------------------------------------------------------
# Each classification answers two questions: did the *representation* change, and
# was *information* lost, transformed, or fabricated relative to the native value.
#
#   equal               compat == native (same type and value)
#   null_both           both NULL (no value / column default absent)
#   representation      only the type/encoding of the same information changed
#   transformed         a lossless but caller-visible conversion (e.g. int -> hex text)
#   dropped             compat returned None although native produced a value
#   multi_unparsed      multi-value stored as one hex blob; element count/types are hidden
#   separated_address   compat returned the 4/8-byte LV address key, not the value
#   hex_of_raw_only     compat hex decodes to the raw on-disk payload, not the logical value
#   fabricated          compat value cannot be derived from native value (hex-of-hex)
#   incompatible        lossy/unsafe: multi-value where empty elements are collapsed,
#
# The first five are "safe to migrate" as long as the caller knows the type. The last
# four require caller changes and are called out in the migration table.

LOSSY = {"dropped", "multi_unparsed", "separated_address", "hex_of_raw_only", "fabricated", "incompatible"}
REPRESENTATIONAL = {"representation", "transformed"}

CLASS_NOTES = {
    "equal": "No change.",
    "null_both": "No change; NULL stays NULL.",
    "representation": "Same information, different Python type/encoding (e.g. str vs hex bytes).",
    "transformed": "Lossless conversion the caller must reverse (e.g. int rendered as hex text).",
    "dropped": "Information LOST: compat returns NULL for a value native can decode.",
    "multi_unparsed": "Information HIDDEN: multi-value returned as one opaque hex blob; element boundaries/types unavailable.",
    "separated_address": "Information LOST: compat returns the long-value address, not the long value.",
    "hex_of_raw_only": "Information HIDDEN: compat hex is the raw on-disk payload (LV address for separated values).",
    "fabricated": "Information FABRICATED: compat hex-encodes an already-hex string (double encoding).",
    "incompatible": "Information LOST: multi-value element boundaries collapse; empty elements cannot be recovered.",
}


def _read_file(path: Path) -> io.BytesIO:
    """Load a fixture into memory (gzip transparently), strictly read-only."""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        return io.BytesIO(fh.read())


def _describe(value: Any, max_repr: int = 60) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return f"{value!r}"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
            if text.isprintable() and len(value) <= max_repr:
                return f"bytes<{len(value)}> {text!r}"
        except Exception:
            pass
        return f"bytes<{len(value)}> {hexlify(value[:max_repr]).decode()}{'...' if len(value) > max_repr else ''}"
    if isinstance(value, str):
        return f"str<{len(value)}> {value[:max_repr]!r}{'...' if len(value) > max_repr else ''}"
    if isinstance(value, list):
        inner = ", ".join(_describe(v, max_repr // 2) for v in value[:4])
        more = ", ..." if len(value) > 4 else ""
        return f"list<{len(value)}> [{inner}{more}]"
    return repr(value)


def _is_hex_ascii(value: Any) -> bool:
    if not isinstance(value, bytes) or not value:
        return False
    if len(value) % 2:
        return False
    try:
        unhexlify(value)
    except Exception:
        return False
    return True


def _raw_bytes(record: Any, name: str) -> bytes | None:
    try:
        raw = record.get(name, raw=True)
    except Exception:
        return None
    if raw is None:
        return None
    return bytes(raw) if isinstance(raw, (bytes, bytearray, memoryview)) else None


def _tag_flags(record: Any, column: Any) -> int | None:
    if not column.is_tagged:
        return None
    try:
        tag, _ = record._data._get_tagged(column)
    except Exception:
        return None
    return None if tag is None else tag.flags


def _default_bytes(column: Any) -> bytes | None:
    try:
        default = column.default
    except Exception:
        return None
    return bytes(default) if isinstance(default, (bytes, bytearray, memoryview)) else None


def _is_multi(flags: int | None) -> bool:
    return bool(flags and (flags & TAGFLD_HEADER.MultiValues))


def _multi_offsets(raw: bytes, flags: int) -> tuple[list[int], int]:
    """Return the element byte spans of a multi-value payload (without decompressing)."""
    if flags & TAGFLD_HEADER.TwoValues:
        first_size = raw[0]
        return [first_size, len(raw) - 1 - first_size], 1
    if flags & TAGFLD_HEADER.MultiValues:
        first = int.from_bytes(raw[0:2], "little") & 0x7FFF
        n = first // 2
        offsets = [int.from_bytes(raw[i : i + 2], "little") & 0x7FFF for i in range(0, first, 2)]
        ends = offsets[1:] + [len(raw)]
        return [e - s for s, e in zip(offsets, ends)], 0
    return [], 0


def _classify(column: Any, flags: int | None, raw: bytes | None, native: Any, compat: Any, default_raw: bytes | None) -> str:
    if native is None and compat is None:
        return "null_both"
    if native is None and compat is not None:
        return "fabricated"
    if compat is None:
        return "dropped"
    if _is_multi(flags):
        # A multi-value with an empty element is the strongest form of loss: the
        # element boundary is present only in the offset table compat discards.
        return "incompatible" if _empty_element_indices(native) else "multi_unparsed"
    if flags and (flags & TAGFLD_HEADER.Separated) and (raw is None or len(raw) in (4, 8)):
        # The on-disk tag value is the long-value address; compat never follows it.
        # Exception: a text column holding a default (no tag field) still decodes the default.
        return "separated_address"
    if isinstance(compat, bytes) and isinstance(native, bytes) and _is_hex_ascii(compat) and unhexlify(compat) == native:
        return "representation"
    if isinstance(compat, bytes) and raw is not None and _is_hex_ascii(compat) and unhexlify(compat) == raw and native != raw:
        return "hex_of_raw_only"
    if isinstance(compat, bytes) and isinstance(native, bytes) and _is_hex_ascii(compat) and unhexlify(compat) != native:
        # compat re-hex-encoded bytes that were already rendered as hex text (column-default path)
        if default_raw is not None and unhexlify(compat) == _hex_text_of(default_raw):
            return "fabricated"
        return "hex_of_raw_only"
    if isinstance(compat, bytes) and isinstance(native, str) and _is_hex_ascii(compat):
        return "transformed"
    if isinstance(compat, str) and isinstance(native, str) and compat != native:
        # A text column whose compat value re-encodes to the hex rendering of the
        # raw/default payload (the default path hex-encodes, then decodes as text).
        if default_raw is not None:
            for enc in ("cp1252", "utf-16-le", "ascii"):
                try:
                    if compat.encode(enc) == _hex_text_of(default_raw):
                        return "fabricated"
                except Exception:
                    continue
        return "representation"
    if type(compat) is not type(native) and native is not None:
        return "representation"
    return "equal" if compat == native else "representation"


def _hex_text_of(value: bytes) -> bytes:
    return hexlify(value)


def _empty_element_indices(native: Any) -> list[int]:
    if not isinstance(native, list):
        return []
    return [i for i, v in enumerate(native) if v in (b"", "", None)]


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def audit_catalog_metadata(native_db: EseDB, compat_db: EseDB) -> dict[str, Any]:
    """Compare metadata derived from the catalog, which also flows through compat parsing.

    Compat mode hex-encodes binary catalog values (``KeyFldIDs``, ``DefaultValue``), so
    anything the library derives from them (index column lists, column sizes/defaults)
    silently changes even before a record is read.
    """
    divergences = []
    for ntable in native_db.tables():
        ctable = compat_db.table(ntable.name)
        for ncol, ccol in zip(ntable.columns, ctable.columns):
            if ncol.size != ccol.size:
                divergences.append(
                    {"table": ntable.name, "column": ncol.name, "field": "size", "native": ncol.size, "compat": ccol.size}
                )
            if ncol.encoding != ccol.encoding:
                divergences.append(
                    {
                        "table": ntable.name,
                        "column": ncol.name,
                        "field": "encoding",
                        "native": str(ncol.encoding),
                        "compat": str(ccol.encoding),
                    }
                )
            ndef, cdef = _default_bytes(ncol), _default_bytes(ccol)
            if ndef != cdef:
                divergences.append(
                    {
                        "table": ntable.name,
                        "column": ncol.name,
                        "field": "default",
                        "native": _describe(ndef),
                        "compat": _describe(cdef),
                    }
                )
        for nidx, cidx in zip(ntable.indexes, ctable.indexes):
            try:
                nids = nidx.column_ids
            except Exception:
                nids = None
            try:
                cids = cidx.column_ids
            except Exception:
                cids = None
            if nids != cids:
                divergences.append(
                    {"table": ntable.name, "index": nidx.name, "field": "column_ids", "native": nids, "compat": cids}
                )
    return {"divergences": divergences}


def audit_db(path: Path) -> dict[str, Any]:
    native_db = EseDB(_read_file(path), impacket_compat=False)
    compat_db = EseDB(_read_file(path), impacket_compat=True)

    report: dict[str, Any] = {
        "database": str(path),
        "page_size": native_db.page_size,
        "catalog": audit_catalog_metadata(native_db, compat_db),
        "tables": [],
    }
    for ntable in native_db.tables():
        ctable = compat_db.table(ntable.name)
        columns = []
        for col in ntable.columns:
            columns.append(
                {
                    "name": col.name,
                    "identifier": col.identifier,
                    "type": col.type.name,
                    "size": col.size,
                    "encoding": col.encoding.name if col.encoding is not None else None,
                    "storage": "fixed" if col.is_fixed else "variable" if col.is_variable else "tagged",
                    "default_hex": hexlify(_default_bytes(col)).decode() if _default_bytes(col) is not None else None,
                }
            )

        table_entry: dict[str, Any] = {
            "name": ntable.name,
            "columns": columns,
            "record_count": 0,
            "field_diffs": [],
            "counts": Counter(),
        }
        # Compat mode must not change the raw bytes a caller can ask for.
        raw_stability_mismatches = 0
        # Pair records by iteration order; both modes see the same leaf nodes.
        for ridx, (nrec, crec) in enumerate(zip(ntable.records(), ctable.records())):
            table_entry["record_count"] += 1
            for col in ntable.columns:
                flags = _tag_flags(nrec, col)
                raw = _raw_bytes(nrec, col.name)
                craw = _raw_bytes(crec, col.name)
                if raw != craw:
                    raw_stability_mismatches += 1
                try:
                    native = nrec.get(col.name)
                except Exception as e:  # pragma: no cover - defensive
                    native = f"!ERROR! {type(e).__name__}: {e}"
                try:
                    compat = crec.get(col.name)
                except Exception as e:  # pragma: no cover - defensive
                    compat = f"!ERROR! {type(e).__name__}: {e}"
                cls = _classify(col, flags, raw, native, compat, _default_bytes(col))
                table_entry["counts"][cls] += 1
                if cls in ("equal", "null_both"):
                    continue

                multi_spans, payload_start = _multi_offsets(raw, flags) if raw and _is_multi(flags) else ([], 0)
                empty_idx = _empty_element_indices(native)
                table_entry["field_diffs"].append(
                    {
                        "record": ridx,
                        "column": col.name,
                        "identifier": col.identifier,
                        "type": col.type.name,
                        "storage": "fixed" if col.is_fixed else "variable" if col.is_variable else "tagged",
                        "flags": str(flags) if flags is not None else None,
                        "raw_len": len(raw) if raw is not None else None,
                        "raw_hex": hexlify(raw).decode() if raw is not None else None,
                        "native_repr": _describe(native),
                        "compat_repr": _describe(compat),
                        "classification": cls,
                        "multi_element_count": len(multi_spans) if multi_spans else None,
                        "multi_element_byte_lengths": multi_spans,
                        "multi_payload_start": payload_start,
                        "empty_element_indices": empty_idx,
                        "information_lost": cls in LOSSY or bool(empty_idx) and cls == "multi_unparsed",
                    }
                )
        table_entry["counts"] = dict(table_entry["counts"])
        table_entry["raw_stability_mismatches"] = raw_stability_mismatches
        report["tables"].append(table_entry)
    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _field_signature(entry: dict[str, Any]) -> tuple:
    """Collapse per-record diffs into one row per (table, column, classification) shape."""
    return (entry["column"], entry["type"], entry["storage"], entry["flags"], entry["classification"], entry["information_lost"])


def print_report(report: dict[str, Any], verbose: bool = False) -> None:
    print(f"\n=== {report['database']} (page_size={report['page_size']}) ===")
    catalog = report.get("catalog", {}).get("divergences", [])
    if catalog:
        print(f"\n  catalog-derived metadata diverges in {len(catalog)} places:")
        for div in catalog[:8]:
            print(f"    {div['table']}.{div.get('column') or div.get('index')} {div['field']}: native={div['native']} compat={div['compat']}")
        if len(catalog) > 8:
            print(f"    ... and {len(catalog) - 8} more (see JSON report)")
    for table in report["tables"]:
        if not table["field_diffs"]:
            continue
        print(f"\n  table {table['name']!r}  ({table['record_count']} records)")
        if table.get("raw_stability_mismatches"):
            print(f"    WARNING: raw=True differs between modes in {table['raw_stability_mismatches']} places")
        if verbose:
            entries = table["field_diffs"]
        else:
            grouped = defaultdict(list)
            for entry in table["field_diffs"]:
                grouped[_field_signature(entry)].append(entry)
            entries = [items[0] for items in grouped.values()]
        for entry in entries:
            marker = "LOSS" if entry["information_lost"] else "    "
            empties = f"  empty_elements={entry['empty_element_indices']}" if entry["empty_element_indices"] else ""
            n = f"  ({len(grouped[_field_signature(entry)])} records)" if not verbose else ""
            print(
                f"    [{marker}] r{entry['record']} {entry['column']} ({entry['type']}/{entry['storage']}"
                f" id={entry['identifier']} flags={entry['flags']}){n}"
                f"\n            raw({entry['raw_len']}) = {entry['raw_hex'][:120] if entry['raw_hex'] else None}"
                f"\n            native = {entry['native_repr']}"
                f"\n            compat = {entry['compat_repr']}"
                f"\n            class  = {entry['classification']}{empties}"
            )


def migration_table(reports: list[dict[str, Any]]) -> str:
    lines = [
        "<!-- generated by audit/ese_compat_audit.py; do not edit by hand -->",
        "",
        "## Field-level migration table",
        "",
        "`Compat representation` is what `impacket_compat=True` returns today. `Native representation` is what",
        "`impacket_compat=False` returns for the same column of the same record. Raw bytes are identical for the",
        "two modes **except** where the table warns below.",
        "",
        "| Table | Column | Type | Storage | Tag flags | Compat representation | Native representation | Classification | Caller action |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    seen = set()
    for report in reports:
        for table in report["tables"]:
            for entry in table["field_diffs"]:
                key = (table["name"], entry["column"], entry["type"], entry["storage"], entry["flags"], entry["classification"])
                if key in seen:
                    continue
                seen.add(key)
                action = ACTION_FOR[entry["classification"]]
                for src in entry["empty_element_indices"]:
                    action += f" Empty element at index {src} cannot be recovered from compat."
                lines.append(
                    "| {t} | {c} | {ty} | {s} | {f} | {cr} | {nr} | {cl} | {a} |".format(
                        t=table["name"],
                        c=entry["column"],
                        ty=entry["type"],
                        s=entry["storage"],
                        f=entry["flags"] or "-",
                        cr=entry["compat_repr"].replace("|", "\\|"),
                        nr=entry["native_repr"].replace("|", "\\|"),
                        cl=entry["classification"],
                        a=action.replace("|", "\\|"),
                    )
                )
    lines.extend(["", "### Catalog-derived metadata divergences", ""])
    lines.append(
        "Compat mode also hex-encodes binary values read from the catalog (`MSysObjects`), so metadata the library"
        " derives from those values changes **before any record is read**: index column id lists become garbage and"
        " `table.search()`, `index.make_key()` and `Cursor` lookups raise `KeyError`. Column `size`/`encoding`/`default`"
        " can also change for columns defined by defaults."
    )
    lines.append("")
    lines.append("| Table | Index/Column | Field | Native | Compat |")
    lines.append("| --- | --- | --- | --- | --- |")
    for report in reports:
        for div in report.get("catalog", {}).get("divergences", []):
            lines.append(
                "| {t} | {n} | {f} | {nv} | {cv} |".format(
                    t=div["table"],
                    n=div.get("column") or div.get("index") or "-",
                    f=div["field"],
                    nv=str(div["native"]).replace("|", "\\|"),
                    cv=str(div["compat"]).replace("|", "\\|"),
                )
            )
    raw_mismatch_tables = [
        (report["database"], table["name"], table["raw_stability_mismatches"])
        for report in reports
        for table in report["tables"]
        if table.get("raw_stability_mismatches")
    ]
    lines.extend(["", "### `raw=True` stability", ""])
    if raw_mismatch_tables:
        lines.append(
            "`record.get(name, raw=True)` is **not** a safe fallback in compat mode. The following tables returned"
            " different raw bytes between the two modes (column-default path hex-encodes before returning):"
        )
        lines.append("")
        for database, table_name, count in raw_mismatch_tables:
            lines.append(f"- `{database}` table `{table_name}`: {count} mismatching fields")
    else:
        lines.append("`record.get(name, raw=True)` returned identical bytes in both modes for this fixture set.")
    return "\n".join(lines) + "\n"


ACTION_FOR = {
    "representation": "Consume the hex string as bytes (unhexlify). Type-only change; no caller data loss.",
    "transformed": "Reverse the textual encoding before use (unhexlify); value is otherwise intact.",
    "dropped": "IMPOSSIBLE: re-read with native mode. Compat returns NULL; no equivalent conversion.",
    "multi_unparsed": "IMPOSSIBLE without native re-read: element count/types/empties are not recoverable. Do not split the blob into a single value.",
    "separated_address": "IMPOSSIBLE without native re-read: compat returned the LV address, not the value. Caller must not treat the address as data.",
    "hex_of_raw_only": "IMPOSSIBLE without native re-read: compat hex is the raw payload, not the logical value.",
    "fabricated": "IMPOSSIBLE: compat value is hex-of-hex; reject it rather than decoding.",
    "incompatible": "IMPOSSIBLE without native re-read: empty elements collapse; caller must switch to native mode.",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="database files (default: tests/_data/*.edb.gz)")
    parser.add_argument("--out", type=Path, default=None, help="write JSON + Markdown report to this prefix")
    parser.add_argument("--json-only", action="store_true", help="suppress the human report")
    args = parser.parse_args()

    paths = args.paths or sorted(Path("tests/_data").glob("*.edb.gz"))
    reports = []
    for path in paths:
        rep = audit_db(path)
        reports.append(rep)
        if not args.json_only:
            print_report(rep)

    totals = Counter()
    for rep in reports:
        for table in rep["tables"]:
            for cls, count in table["counts"].items():
                totals[cls] += count
            for entry in table["field_diffs"]:
                if entry["information_lost"]:
                    totals["LOSSY_FIELDS"] += 1
    print("\n=== summary ===")
    for cls, count in sorted(totals.items()):
        print(f"  {cls:22s} {count}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(reports, indent=2, default=str)
        args.out.with_suffix(".json").write_text(payload)
        args.out.with_suffix(".md").write_text(migration_table(reports))
        print(f"\nwrote {args.out.with_suffix('.json')} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
