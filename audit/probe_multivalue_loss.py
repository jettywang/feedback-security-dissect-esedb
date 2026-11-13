#!/usr/bin/env python3
"""Demonstrate that ``impacket_compat`` can silently lose multi-value structure.

This script does three things, all read-only with respect to the fixture files:

1. Picks a real multi-value column from ``tests/_data/multi.edb.gz`` and shows the
   native list, the compat blob, and the raw on-disk bytes side by side.
2. Builds an *in-memory* copy of the same fixture whose ``LongASCII`` multi-value
   contains an empty first element (the payload offsets are rewritten to ``[4, 4]``,
   which stores ``""`` followed by both strings). It then shows:
      - native parsing returns ``["", "Tiny ASCII 1Tiny ASCII 2"]``
      - compat returns a single opaque hex blob
      - two naive migrations (",".join / split-on-NUL) both produce a wrong value
      - the audit module flags the field as lossy
3. Exercises the real ``RecordData._parse_multivalue`` on synthetic payloads with
   empty elements at different positions, so the loss is proven independent of the
   fixture's exact contents.

Exit code 1 if the audit fails to detect the injected empty element.
"""

from __future__ import annotations

import gzip
import io
import sys
from binascii import hexlify, unhexlify
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ese_compat_audit import audit_db  # noqa: E402

from dissect.esedb import EseDB  # noqa: E402
from dissect.esedb.c_esedb import JET_coltyp, TAGFLD_HEADER  # noqa: E402
from dissect.esedb.record import RecordData  # noqa: E402
from dissect.esedb.table import Column  # noqa: E402

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "_data" / "multi.edb.gz"
ORIGINAL_PAYLOAD = bytes.fromhex("04001000") + b"Tiny ASCII 1" + b"Tiny ASCII 2"
PATCHED_PAYLOAD = b"\x04\x00\x04\x00" + b"Tiny ASCII 1" + b"Tiny ASCII 2"


def load_bytes() -> bytes:
    with gzip.open(FIXTURE, "rb") as fh:
        return fh.read()


def to_db(data: bytes, compat: bool) -> EseDB:
    return EseDB(io.BytesIO(data), impacket_compat=compat)


def show_real_column() -> None:
    data = load_bytes()
    native = list(to_db(data, False).table("multi").records())[1]
    compat = list(to_db(data, True).table("multi").records())[1]
    raw = native.get("LongASCII", raw=True)
    print("== real multi-value (multi.edb, record Id=2, LongASCII) ==")
    print(f"  raw on disk : {hexlify(raw).decode()}")
    print(f"  native      : {native.get('LongASCII')!r}")
    print(f"  compat      : {compat.get('LongASCII')!r}")


def naive_migrations(blob: bytes, encoding: str) -> dict[str, str]:
    """Three plausible 'migrations' that look reasonable and are all wrong."""
    decoded = unhexlify(blob).decode(encoding, "replace")
    return {
        "strip offset table, decode": decoded[4:],
        "split on NUL": decoded.replace("\x00", " | "),
        "treat as one value": decoded,
    }


def show_patched_column() -> bool:
    data = load_bytes()
    assert data.count(ORIGINAL_PAYLOAD) == 1, "fixture layout changed; update the probe"
    patched = data.replace(ORIGINAL_PAYLOAD, PATCHED_PAYLOAD, 1)

    native = list(to_db(patched, False).table("multi").records())[1]
    compat = list(to_db(patched, True).table("multi").records())[1]
    native_value = native.get("LongASCII")
    compat_value = compat.get("LongASCII")
    raw = native.get("LongASCII", raw=True)
    column = native._table.column("LongASCII")
    encoding = "cp1252" if column.encoding is None else {"WESTERN": "cp1252", "UNICODE": "utf-16-le", "ASCII": "ascii"}[column.encoding.name]

    print("\n== in-memory patch: same record, first element made empty ==")
    print(f"  raw on disk : {hexlify(raw).decode()}")
    print(f"  native      : {native_value!r}")
    print(f"  compat      : {compat_value!r}")
    print(f"  native len  : {len(native_value)} elements; compat type: {type(compat_value).__name__}")

    assert native_value == ["", "Tiny ASCII 1Tiny ASCII 2"], native_value
    assert isinstance(compat_value, bytes)

    print("\n  naive migrations of the compat blob:")
    for name, result in naive_migrations(compat_value, encoding).items():
        print(f"    {name:30s} -> {result!r}")
    print(
        "  None of these recover the empty element: the hex blob encodes only byte\n"
        "  offsets, and both an empty element and a merged element look like text."
    )

    # Feed the patched bytes through the audit module by writing to a temp dir that is
    # outside the repository fixture tree, never over the fixtures themselves.
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".edb", delete=False) as tmp:
        tmp.write(patched)
        tmp_path = Path(tmp.name)
    try:
        report = audit_db(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    hits = [
        entry
        for table in report["tables"]
        if table["name"] == "multi"
        for entry in table["field_diffs"]
        if entry["column"] == "LongASCII"
    ]
    print("\n  audit module detection:")
    for entry in hits:
        print(
            f"    record={entry['record']} class={entry['classification']} lost={entry['information_lost']} "
            f"empty_indices={entry['empty_element_indices']} "
            f"element_sizes={entry['multi_element_byte_lengths']}"
        )

    patched_hits = [entry for entry in hits if entry["record"] == 1]
    detected = (
        bool(patched_hits)
        and patched_hits[0]["information_lost"]
        and patched_hits[0]["empty_element_indices"] == [0]
        and patched_hits[0]["multi_element_byte_lengths"] == [0, 24]
    )
    print(f"  detection result: {'PASS' if detected else 'FAIL'}")
    return detected


def probe_default_paths() -> bool:
    """Show the column-default path in compat mode parses hex text as the raw value.

    This runs the real ``RecordData._parse_value`` against each column's own
    ``default``. When a record omits a fixed/variable column, ``_get_fixed`` /
    ``_get_variable`` return ``column.default``, which compat has already hex-encoded;
    parsing that hex text as the column type produces a different value (or raises).
    """
    data = load_bytes()
    del data  # only the default fixture has declared defaults

    class _Table:
        def __init__(self, esedb):
            self.esedb = esedb

    class _Record(RecordData):
        def __init__(self, esedb):
            self.esedb = esedb
            self.table = _Table(esedb)

    # The `default.edb` fixture is the one with declared defaults; reopen it.
    with gzip.open(FIXTURE.parent / "default.edb.gz", "rb") as fh:
        default_data = fh.read()

    print("\n== column-default path (real RecordData._parse_value on Column.default) ==")
    results = {}
    diverged = 0
    for compat in (False, True):
        db = to_db(default_data, compat)
        table = db.table("default")
        record = _Record(db)
        label = "compat" if compat else "native"
        for name in ("Bit", "UnsignedByte", "Short", "Long", "GUID", "IEEESingle", "Binary", "Unicode"):
            column = table.column(name)
            try:
                value = record._parse_value(column, column.default, None)
                result = repr(value)
            except Exception as exc:  # noqa: BLE001 - we are proving the failure
                result = f"{type(exc).__name__}: {exc}"
            results[(label, name)] = result
            print(f"  {label:6s} {name:12s} default={column.default!r:34s} -> {result}")

    for name in ("Bit", "UnsignedByte", "Short", "Long", "GUID", "IEEESingle", "Binary", "Unicode"):
        if results[("native", name)] != results[("compat", name)]:
            diverged += 1

    nbit = to_db(default_data, False).table("default").column("Bit").default
    cbit = to_db(default_data, True).table("default").column("Bit").default
    print(f"  default bytes: native Bit={nbit!r} compat Bit={cbit!r}")
    print(f"  divergent defaults: {diverged} (GUID raises ValueError in compat)")
    return diverged >= 6 and cbit == b"01"


def synthetic_multi_payloads() -> bool:
    """Prove empty-element loss directly on the parser, independent of fixtures."""

    class _Db:
        impacket_compat = False
        has_small_pages = True

    class _Table:
        def __init__(self) -> None:
            self.esedb = _Db()

        def get_long_value(self, key: bytes) -> bytes:
            raise AssertionError("synthetic payload has no separated elements")

    class _Record(RecordData):
        def __init__(self) -> None:
            self.table = _Table()
            self.esedb = _Db()

    class _Tag:
        def __init__(self, flags: int) -> None:
            self.flags = flags

    column = Column(256, "MV", JET_coltyp.Text)
    multi_tag = _Tag(TAGFLD_HEADER.MultiValues)

    cases = {
        "empty first": bytes.fromhex("060006000600"),
        "empty middle": bytes.fromhex("06000600070078"),
        "text with empty middle": bytes.fromhex("060007000700616263"),
    }
    print("\n== synthetic multi-value payloads (real RecordData._parse_multivalue) ==")
    ok = True
    for name, payload in cases.items():
        value = _Record()._parse_multivalue(payload, multi_tag)
        compat_blob = hexlify(payload)
        print(f"  {name:24s} raw={payload.hex():18s} native={value!r:40s} compat={compat_blob!r}")
        if not any(x in (b"", "", None) for x in value):
            ok = False
            print(f"    expected an empty element in {value!r}")
    return ok


def main() -> int:
    show_real_column()
    empty_ok = show_patched_column()
    synthetic_ok = synthetic_multi_payloads()
    defaults_ok = probe_default_paths()
    print(f"\noverall: {'PASS' if empty_ok and synthetic_ok and defaults_ok else 'FAIL'}")
    return 0 if empty_ok and synthetic_ok and defaults_ok else 1


if __name__ == "__main__":
    sys.exit(main())
