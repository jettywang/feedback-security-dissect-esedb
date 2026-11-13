from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.esedb.c_esedb import PAGE_FLAG, TAGFLD_HEADER, JET_coltyp
from dissect.esedb.esedb import EseDB
from dissect.esedb.record import RecordData, ValueSource
from dissect.esedb.table import Column, Table

if TYPE_CHECKING:
    from dissect.esedb.record import FieldInfo


def _make_table(columns: list[Column]) -> Table:
    esedb = SimpleNamespace(has_small_pages=False, impacket_compat=False)
    return Table(esedb, "synthetic", 0, columns=columns)


def _make_node(data: bytes) -> SimpleNamespace:
    return SimpleNamespace(data=data, tag=SimpleNamespace(page=SimpleNamespace(flags=PAGE_FLAG.NewRecordFormat)))


class _SyntheticRecord:
    """A minimal ``Record`` compatible wrapper around a synthetic :class:`RecordData`."""

    def __init__(self, data: RecordData) -> None:
        self._data = data

    def get(self, attr: str, raw: bool = False) -> object:
        return self._data.get(self._data.table.column(attr), raw)

    def field_info(self, attr: str, **kwargs: object) -> FieldInfo:
        return self._data.field_info(self._data.table.column(attr), **kwargs)

    def as_dict(self, raw: bool = False) -> dict:
        return self._data.as_dict(raw)


def _fixed_record_data() -> RecordData:
    """A record with only fixed columns, covering stored, explicit null, default and missing."""
    table = _make_table(
        [
            Column(1, "FixedStored", JET_coltyp.Long),
            Column(2, "FixedNull", JET_coltyp.Long),
            Column(3, "FixedDefault", JET_coltyp.Long),
            Column(4, "FixedMissing", JET_coltyp.Long),
        ]
    )
    table.column("FixedNull").default = struct.pack("<i", 0xBAD)
    table.column("FixedDefault").default = struct.pack("<i", 0xF00D)

    fixed_data = struct.pack("<ii", 1337, 0)
    null_bitmap = b"\x02"  # the second fixed column is explicitly null
    header = struct.pack("<BBH", 2, 127, 4 + len(fixed_data) + len(null_bitmap))
    return RecordData(table, _make_node(header + fixed_data + null_bitmap))


def _variable_record_data() -> RecordData:
    """A record with only variable columns, covering stored, empty, explicit null, default and missing."""
    table = _make_table(
        [
            Column(128, "VarStored", JET_coltyp.Binary),
            Column(129, "VarEmpty", JET_coltyp.Binary),
            Column(130, "VarNull", JET_coltyp.Binary),
            Column(131, "VarDefault", JET_coltyp.Binary),
            Column(132, "VarMissing", JET_coltyp.Binary),
        ]
    )
    table.column("VarNull").default = b"null-default"
    table.column("VarDefault").default = b"default-value"

    variable_data = b"AB"
    offsets = struct.pack("<HHH", 2, 2, 0x8002)  # stored, empty, null
    header = struct.pack("<BBH", 0, 130, 4)
    return RecordData(table, _make_node(header + offsets + variable_data))


def _tagged_record_data() -> RecordData:
    """A record with only tagged columns, covering all sources, including multi-values."""
    table = _make_table(
        [
            Column(256, "TagStored", JET_coltyp.Binary),
            Column(257, "TagNull", JET_coltyp.Binary),
            Column(258, "TagEmpty", JET_coltyp.Binary),
            Column(259, "TagMultiEmpty", JET_coltyp.LongBinary),
            Column(260, "TagMulti", JET_coltyp.LongBinary),
            Column(261, "TagDefault", JET_coltyp.Binary),
            Column(262, "TagMissing", JET_coltyp.Binary),
            Column(263, "TagMultiCorrupt", JET_coltyp.LongBinary),
        ]
    )
    table.column("TagNull").default = b"null-default"
    table.column("TagDefault").default = b"default-value"

    regions = [
        (256, 0x00, b"XY"),
        (257, int(TAGFLD_HEADER.Null), b""),
        (258, 0x00, b""),
        (259, int(TAGFLD_HEADER.MultiValues), b""),
        (260, int(TAGFLD_HEADER.MultiValues), b"\x04\x00\x05\x00abb"),
        (263, int(TAGFLD_HEADER.MultiValues), b"\xff\xff"),
    ]
    offset = 4 * len(regions)  # the TAGFLD array comes first
    tagflds = []
    fields = b""
    for identifier, flags, data in regions:
        tagflds.append(struct.pack("<I", identifier | (offset << 16)))
        fields += bytes([flags]) + data
        offset += 1 + len(data)

    header = struct.pack("<BBH", 0, 127, 4)
    return RecordData(table, _make_node(header + b"".join(tagflds) + fields))


def test_field_info_fixed() -> None:
    data = _fixed_record_data()

    info = data.field_info(data.table.column("FixedStored"))
    assert info.source is ValueSource.STORED
    assert info.value == 1337
    assert info.raw == struct.pack("<i", 1337)
    assert (info.offset, info.size) == (4, 4)
    assert data.data[info.offset : info.offset + info.size] == info.raw

    # An explicit null must not be masked by the column default
    info = data.field_info(data.table.column("FixedNull"))
    assert info.source is ValueSource.NULL
    assert info.value is None
    assert info.raw is None
    assert (info.offset, info.size) == (8, 4)

    info = data.field_info(data.table.column("FixedDefault"))
    assert info.source is ValueSource.DEFAULT
    assert info.value == 0xF00D
    assert info.raw == struct.pack("<i", 0xF00D)
    assert (info.offset, info.size) == (None, None)

    info = data.field_info(data.table.column("FixedMissing"))
    assert info.source is ValueSource.MISSING
    assert info.value is None
    assert info.raw is None
    assert (info.offset, info.size) == (None, None)


def test_field_info_variable() -> None:
    data = _variable_record_data()

    info = data.field_info(data.table.column("VarStored"))
    assert info.source is ValueSource.STORED
    assert info.value == b"AB"
    assert info.raw == b"AB"
    assert (info.offset, info.size) == (10, 2)
    assert data.data[info.offset : info.offset + info.size] == info.raw

    # Zero-length data is stored, which is different from a null or a missing column
    info = data.field_info(data.table.column("VarEmpty"))
    assert info.source is ValueSource.EMPTY
    assert info.value == b""
    assert info.raw == b""
    assert (info.offset, info.size) == (12, 0)

    # An explicit null must not be masked by the column default
    info = data.field_info(data.table.column("VarNull"))
    assert info.source is ValueSource.NULL
    assert info.value is None
    assert info.raw is None

    info = data.field_info(data.table.column("VarDefault"))
    assert info.source is ValueSource.DEFAULT
    assert info.value == b"default-value"
    assert info.raw == b"default-value"

    info = data.field_info(data.table.column("VarMissing"))
    assert info.source is ValueSource.MISSING
    assert info.value is None
    assert info.raw is None


def test_field_info_tagged() -> None:
    data = _tagged_record_data()

    info = data.field_info(data.table.column("TagStored"))
    assert info.source is ValueSource.STORED
    assert info.value == b"XY"
    assert info.raw == b"XY"
    assert (info.offset, info.size) == (29, 2)
    assert data.data[info.offset : info.offset + info.size] == info.raw
    assert info.tag_field is not None

    # An explicit null must not be masked by the column default
    info = data.field_info(data.table.column("TagNull"))
    assert info.source is ValueSource.NULL
    assert info.value is None
    assert info.raw is None

    info = data.field_info(data.table.column("TagEmpty"))
    assert info.source is ValueSource.EMPTY
    assert info.value == b""
    assert info.raw == b""
    assert info.size == 0

    info = data.field_info(data.table.column("TagDefault"))
    assert info.source is ValueSource.DEFAULT
    assert info.value == b"default-value"
    assert info.raw == b"default-value"

    info = data.field_info(data.table.column("TagMissing"))
    assert info.source is ValueSource.MISSING
    assert info.value is None
    assert info.raw is None


def test_field_info_multivalue() -> None:
    data = _tagged_record_data()

    info = data.field_info(data.table.column("TagMulti"))
    assert info.source is ValueSource.STORED
    assert info.value == [b"a", b"bb"]
    assert info.raw == b"\x04\x00\x05\x00abb"
    assert (info.offset, info.size) == (35, 7)
    assert data.data[info.offset : info.offset + info.size] == info.raw

    # An empty multi-value list is stored as zero-length data, which is different from a missing column
    info = data.field_info(data.table.column("TagMultiEmpty"))
    assert info.source is ValueSource.EMPTY
    assert info.value == []
    assert info.raw == b""
    assert info.size == 0

    info = data.field_info(data.table.column("TagMissing"))
    assert info.source is ValueSource.MISSING
    assert info.value is None
    assert info.raw is None

    # A multi-value with garbage offsets is stored, but cannot be parsed
    info = data.field_info(data.table.column("TagMultiCorrupt"))
    assert info.source is ValueSource.CORRUPT
    assert info.value is None
    assert info.raw == b"\xff\xff"
    assert info.error is not None
    with pytest.raises(struct.error):
        data.get(data.table.column("TagMultiCorrupt"))


def test_field_info_fixed_real_db(basic_db: BinaryIO) -> None:
    db = EseDB(basic_db)

    table = db.table("basic")
    records = list(table.records())

    info = records[0].field_info("Id")
    assert info.source is ValueSource.STORED
    assert info.value == 1
    assert info.raw == records[0].get("Id", raw=True)
    assert (info.offset, info.size) == (4, 4)

    # The second record has no fixed columns beyond Id stored, and they have no default
    info = records[1].field_info("UnsignedLong")
    assert info.source is ValueSource.MISSING
    assert info.value is None
    assert records[1].get("UnsignedLong") is None

    # The catalog has explicit null fixed columns (RootFlag is only set on table root records)
    catalog = db.table("MSysObjects")
    null_infos = [rec.field_info("RootFlag") for rec in catalog.records()]
    assert any(info.source is ValueSource.NULL for info in null_infos)
    assert any(info.source is ValueSource.STORED for info in null_infos)

    # The catalog also has explicit null variable columns
    stats_infos = [rec.field_info("Stats") for rec in catalog.records()]
    assert any(info.source is ValueSource.NULL for info in stats_infos)
    assert any(info.source is ValueSource.MISSING for info in stats_infos)


def test_field_info_default_real_db(default_db: BinaryIO) -> None:
    db = EseDB(default_db)
    table = db.table("default")
    record = list(table.records())[0]

    # Physically stored, happens to be equal to the column default
    info = record.field_info("Id")
    assert info.source is ValueSource.STORED
    assert info.value == 1

    # Not stored in the record, value comes from the column default
    info = record.field_info("LongBinary")
    assert info.source is ValueSource.DEFAULT
    assert info.value == b"Long default binary " + (b"a" * 200)
    assert info.raw == table.column("LongBinary").default
    assert (info.offset, info.size) == (None, None)
    assert record.get("LongBinary", raw=True) == info.raw


def test_field_info_tagged_real_db(multi_db: BinaryIO, windows_search_db: BinaryIO) -> None:
    db = EseDB(multi_db)
    table = db.table("multi")
    records = list(table.records())

    info = records[0].field_info("Bit")
    assert info.source is ValueSource.STORED
    assert info.value == [False, True]
    assert info.raw == records[0].get("Bit", raw=True)
    assert info.tag_field is not None
    assert records[0]._data.data[info.offset : info.offset + info.size] == info.raw

    # The second record does not store this tagged column at all
    info = records[1].field_info("Bit")
    assert info.source is ValueSource.MISSING
    assert info.value is None
    assert records[1].get("Bit") is None

    # A real database with zero-length tagged data
    db = EseDB(windows_search_db)
    table = db.table("SystemIndex_1_Properties")
    empty_infos = [rec.field_info("Property") for rec in table.records()]
    assert any(info.source is ValueSource.EMPTY for info in empty_infos)
    for info in empty_infos:
        if info.source is ValueSource.EMPTY:
            assert info.value == b""
            assert info.raw == b""
            assert info.size == 0


def test_field_info_corrupt_real_db(windows_search_db: BinaryIO) -> None:
    db = EseDB(windows_search_db)
    table = db.table("SystemIndex_PropertyStore")
    record = table.search(WorkID=1017)

    column = table.column("4625-System_Search_AutoSummary")

    # The value contains invalid utf-16-le, which is only observable with strict error handling
    info = record.field_info(column.name, errors="strict")
    assert info.source is ValueSource.CORRUPT
    assert info.value is None
    assert info.raw is not None
    assert info.error is not None

    # With the default error handling the same source is reported as stored
    info = record.field_info(column.name)
    assert info.source is ValueSource.STORED
    assert info.value == record.get(column.name)


def test_field_info_state_table(basic_db: BinaryIO, default_db: BinaryIO, multi_db: BinaryIO) -> None:
    """Combine the different sources in a small table, showing the different evidence behind the same
    displayed value, and verify that the access order does not change the provenance."""
    rows: list[tuple[str, object, str, FieldInfo]] = []

    def add(label: str, record: object, attr: str, **kwargs: object) -> None:
        info = record.field_info(attr, **kwargs)
        rows.append((label, record, attr, info))

    db = EseDB(basic_db)
    catalog_record = next(rec for rec in db.table("MSysObjects").records() if rec.field_info("RootFlag").is_null)
    add("null fixed", catalog_record, "RootFlag")
    add("missing fixed", list(db.table("basic").records())[1], "UnsignedLong")

    db = EseDB(default_db)
    add("default tagged", list(db.table("default").records())[0], "LongBinary")

    db = EseDB(multi_db)
    multi_records = list(db.table("multi").records())
    add("stored multi", multi_records[0], "Bit")
    add("missing tagged", multi_records[1], "Bit")

    synthetic = _SyntheticRecord(_tagged_record_data())
    add("empty multi", synthetic, "TagMultiEmpty")
    add("corrupt multi", synthetic, "TagMultiCorrupt")

    displayed: dict[str, set[ValueSource]] = {}
    table_lines = ["label           display             source   offset size  raw"]
    for label, record, attr, info in rows:
        display = repr(info.value)
        displayed.setdefault(display, set()).add(info.source)
        table_lines.append(
            f"{label:<15} {display:<19} {info.source!s:<8} {info.offset!s:<6} {info.size!s:<5} {info.raw!r}"
        )

        # Raw and decoded access must agree with the provenance of the same source
        if not info.is_corrupt:
            assert record.get(attr) == info.value
        assert record.get(attr, raw=True) == info.raw

        # The access order must not change the provenance
        record.as_dict()
        assert record.field_info(attr) == info

    print("\n" + "\n".join(table_lines))

    # The same displayed value ``None`` has three different kinds of evidence
    assert displayed["None"] == {ValueSource.NULL, ValueSource.MISSING, ValueSource.CORRUPT}
    # An empty multi-value list and a missing column both look empty, but are distinct
    assert displayed["[]"] == {ValueSource.EMPTY}
    assert displayed["[False, True]"] == {ValueSource.STORED}


def test_field_info_access_order() -> None:
    """The provenance of a value must not depend on whether raw, decoded or dictionary access came first."""
    for make_record_data in (_fixed_record_data, _variable_record_data, _tagged_record_data):
        data = make_record_data()
        for column in data.table.columns:
            info_first = data.field_info(column)

            if not info_first.is_corrupt:
                assert data.get(column) == info_first.value
            assert data.get(column, raw=True) == info_first.raw
            data.as_dict()
            data.as_dict(raw=True)

            assert data.field_info(column) == info_first

        # A fresh record data instance must come to the same conclusion
        fresh = make_record_data()
        for column in fresh.table.columns:
            if fresh.field_info(column).is_corrupt:
                continue
            fresh.get(column)
            fresh.get(column, raw=True)
            assert fresh.field_info(column) == data.field_info(column)
