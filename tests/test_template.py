from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dissect.esedb.c_esedb import JET_coltyp, TAGFLD_HEADER
from dissect.esedb.exceptions import InvalidDatabase
from dissect.esedb.record import Record
from dissect.esedb.table import Catalog, Column, Table


def _mock_esedb() -> MagicMock:
    esedb = MagicMock()
    esedb.has_small_pages = True
    esedb.impacket_compat = False
    return esedb


def _catalog_column_record(
    identifier: int,
    name: str,
    coltyp: JET_coltyp,
    default: bytes | None = None,
    space_usage: int | None = None,
) -> MagicMock:
    record = MagicMock()
    record.get = lambda key: {
        "Id": identifier,
        "Name": name,
        "ColtypOrPgnoFDP": coltyp.value,
        "DefaultValue": default,
        "SpaceUsage": space_usage,
        "PagesOrLocale": 20127,
    }.get(key)
    return record


def _catalog_table_record(name: str, template: str | None = None) -> MagicMock:
    record = MagicMock()
    record.get = lambda key: {"Name": name, "TemplateTable": template, "ColtypOrPgnoFDP": 1}.get(key)
    return record


def _tag_word(identifier: int, offset: int, derived: bool = False, null: bool = False) -> int:
    """Build a small-page TAGFLD word.

    The 16-bit offset word lays out as: bits 0-12 the relative offset (maskIb), bit 13 fNullSmallPage,
    bit 14 fExtendedInfo and bit 15 fDerived.
    """
    word = offset & 0x1FFF
    if not null:
        word |= 1 << 14  # fExtendedInfo
    if derived:
        word |= 1 << 15  # fDerived
    if null:
        word |= 1 << 13  # fNullSmallPage
    return (word << 16) | identifier


def _record(table: Table, data: bytes) -> Record:
    page = MagicMock()
    page.flags = 0x800  # PAGE_FLAG.NewRecordFormat
    node = MagicMock()
    node.data = data
    node.tag.page = page
    return Record(table, node)


@pytest.fixture
def derived_table() -> Table:
    """A derived table merging a template column set with its own columns.

    Template (inherited) columns: a fixed Long (id 1) and a tagged Binary (id 256), plus a tagged Binary with a
    default value (id 258). The derived table itself adds a fixed Short (id 2) and a tagged Binary (id 257).
    """
    esedb = _mock_esedb()
    return Table(
        esedb,
        "derived",
        99,
        columns=[
            Column(
                1,
                "InheritedLong",
                JET_coltyp.Long,
                record=_catalog_column_record(1, "InheritedLong", JET_coltyp.Long),
                inherited=True,
            ),
            Column(2, "OwnShort", JET_coltyp.Short, record=_catalog_column_record(2, "OwnShort", JET_coltyp.Short)),
            Column(
                256,
                "InheritedTag",
                JET_coltyp.Binary,
                record=_catalog_column_record(256, "InheritedTag", JET_coltyp.Binary),
                inherited=True,
            ),
            Column(257, "OwnTag", JET_coltyp.Binary, record=_catalog_column_record(257, "OwnTag", JET_coltyp.Binary)),
            Column(
                258,
                "InheritedDefaultTag",
                JET_coltyp.Binary,
                record=_catalog_column_record(258, "InheritedDefaultTag", JET_coltyp.Binary, default=b"PARENT-DEFAULT"),
                inherited=True,
            ),
        ],
    )


def test_derived_table_fixed_offsets_follow_column_identifiers(derived_table: Table) -> None:
    # Fixed offsets must be derived from the column identifier, not from catalog/insertion order.
    assert derived_table.column("InheritedLong").offset == 0
    assert derived_table.column("OwnShort").offset == 4


def test_derived_table_record_layout(derived_table: Table) -> None:
    # Hand-crafted small-page record. Fixed section: 4-byte RECHDR + Long(4) + Short(2) + 1 null bitmap byte.
    end_of_fixed = 4 + 4 + 2 + 1  # 11
    tag_array_size = 12  # 3 TAGFLD entries, the parser derives count = first_offset // 4

    # Tagged data regions are a flag byte (1) followed by the raw value. Offsets are relative to the tagged start.
    inherited_value = b"inherited"
    own_value = b"own"
    inherited_offset = tag_array_size
    own_offset = inherited_offset + 1 + len(inherited_value)
    null_offset = own_offset + 1 + len(own_value)

    data = bytes([2, 127, end_of_fixed, 0])
    data += (0x11223344).to_bytes(4, "little")  # InheritedLong (id 1), fixed offset 0
    data += (0x7FFF).to_bytes(2, "little")  # OwnShort (id 2), fixed offset 4
    data += b"\x00"  # fixed null bitmap, both fixed columns are present

    # TAGFLD array, stored in engine sorted order (derived/own distinguished via the fDerived bit).
    data += _tag_word(256, inherited_offset, derived=True).to_bytes(4, "little")
    data += _tag_word(257, own_offset, derived=False).to_bytes(4, "little")
    # A derived null tagged field has no flag byte; its offset points at the current end of the tagged data.
    data += _tag_word(258, null_offset, derived=True, null=True).to_bytes(4, "little")

    # Tagged data region: a flag byte followed by the value for each non-null field.
    data += bytes([TAGFLD_HEADER.Invalid]) + inherited_value
    data += bytes([TAGFLD_HEADER.Invalid]) + own_value

    record = _record(derived_table, data)

    assert record.get("InheritedLong") == 0x11223344
    assert record.get("OwnShort") == 0x7FFF
    assert record.get("InheritedTag") == b"inherited"
    assert record.get("OwnTag") == b"own"
    # The null derived tagged column falls back to the template column's default value.
    assert record.get("InheritedDefaultTag") == b"PARENT-DEFAULT"

    assert record.as_dict() == {
        "InheritedLong": 0x11223344,
        "OwnShort": 0x7FFF,
        "InheritedTag": b"inherited",
        "OwnTag": b"own",
        "InheritedDefaultTag": b"PARENT-DEFAULT",
    }


def test_derived_table_null_fixed_and_missing_tagged(derived_table: Table) -> None:
    # A record without any tagged section: all tagged columns fall back to None or their default.
    end_of_fixed = 4 + 4 + 2 + 1
    data = bytes([2, 127, end_of_fixed, 0])
    data += (0).to_bytes(4, "little")
    data += (0).to_bytes(2, "little")
    data += bytes([0b11])  # both fixed columns marked null in the bitmap

    record = _record(derived_table, data)

    assert record.get("InheritedLong") is None
    assert record.get("OwnShort") is None
    assert record.get("InheritedTag") is None
    assert record.get("OwnTag") is None
    assert record.get("InheritedDefaultTag") == b"PARENT-DEFAULT"


def _new_catalog() -> Catalog:
    catalog = Catalog.__new__(Catalog)
    catalog.esedb = _mock_esedb()
    catalog.tables = []
    catalog._table_name_map = {}
    return catalog


def _register(catalog: Catalog, table: Table) -> None:
    catalog.tables.append(table)
    catalog._table_name_map[table.name] = table


def test_catalog_resolves_template_columns() -> None:
    catalog = _new_catalog()

    parent = Table(catalog.esedb, "parent", 1, record=_catalog_table_record("parent"))
    parent._add_column(
        Column(1, "ParentLong", JET_coltyp.Long, record=_catalog_column_record(1, "ParentLong", JET_coltyp.Long))
    )
    parent._add_column(
        Column(
            256,
            "ParentTag",
            JET_coltyp.Binary,
            record=_catalog_column_record(256, "ParentTag", JET_coltyp.Binary, default=b"PARENT-DEFAULT"),
        )
    )

    child = Table(catalog.esedb, "child", 2, record=_catalog_table_record("child", "parent"))
    child._add_column(
        Column(2, "ChildShort", JET_coltyp.Short, record=_catalog_column_record(2, "ChildShort", JET_coltyp.Short))
    )
    child._add_column(
        Column(257, "ChildTag", JET_coltyp.Binary, record=_catalog_column_record(257, "ChildTag", JET_coltyp.Binary))
    )

    _register(catalog, parent)
    _register(catalog, child)
    catalog._resolve_template(child)

    assert [column.name for column in child.columns] == ["ParentLong", "ParentTag", "ChildShort", "ChildTag"]
    assert [column.inherited for column in child.columns] == [True, True, False, False]

    # Inherited columns keep their template identifiers and defaults.
    assert child.column("ParentLong").identifier == 1
    assert child.column("ParentTag").default == b"PARENT-DEFAULT"

    # Fixed offsets are recalculated based on identifier across the merged column set.
    assert child.column("ParentLong").offset == 0
    assert child.column("ChildShort").offset == 4

    # The template table itself is not mutated by resolving a derived table.
    assert all(not column.inherited for column in parent.columns)


def test_catalog_resolves_multilevel_template_chain() -> None:
    catalog = _new_catalog()

    grandparent = Table(catalog.esedb, "grandparent", 1, record=_catalog_table_record("grandparent"))
    grandparent._add_column(
        Column(1, "Gp", JET_coltyp.Long, record=_catalog_column_record(1, "Gp", JET_coltyp.Long))
    )
    middle = Table(catalog.esedb, "middle", 1, record=_catalog_table_record("middle", "grandparent"))
    middle._add_column(Column(2, "Mid", JET_coltyp.Long, record=_catalog_column_record(2, "Mid", JET_coltyp.Long)))
    bottom = Table(catalog.esedb, "bottom", 1, record=_catalog_table_record("bottom", "middle"))
    bottom._add_column(Column(3, "Bot", JET_coltyp.Long, record=_catalog_column_record(3, "Bot", JET_coltyp.Long)))

    for table in (grandparent, middle, bottom):
        _register(catalog, table)
    catalog._resolve_template(bottom)

    assert [column.name for column in bottom.columns] == ["Gp", "Mid", "Bot"]
    assert [column.inherited for column in bottom.columns] == [True, True, False]


def test_catalog_missing_template_fails() -> None:
    catalog = _new_catalog()
    orphan = Table(catalog.esedb, "orphan", 1, record=_catalog_table_record("orphan", "missing"))
    _register(catalog, orphan)

    with pytest.raises(InvalidDatabase, match="missing template table 'missing'"):
        catalog._resolve_template(orphan)


def test_catalog_cyclic_inheritance_fails() -> None:
    catalog = _new_catalog()
    first = Table(catalog.esedb, "first", 1, record=_catalog_table_record("first", "second"))
    second = Table(catalog.esedb, "second", 1, record=_catalog_table_record("second", "first"))
    _register(catalog, first)
    _register(catalog, second)

    with pytest.raises(InvalidDatabase, match="Cyclic template table inheritance"):
        catalog._resolve_template(first)


def test_catalog_self_inheritance_fails() -> None:
    catalog = _new_catalog()
    table = Table(catalog.esedb, "self", 1, record=_catalog_table_record("self", "self"))
    _register(catalog, table)

    with pytest.raises(InvalidDatabase, match="Cyclic template table inheritance"):
        catalog._resolve_template(table)


def test_catalog_duplicate_identifier_conflict_fails() -> None:
    catalog = _new_catalog()
    parent = Table(catalog.esedb, "parent", 1, record=_catalog_table_record("parent"))
    parent._add_column(
        Column(1, "Parent", JET_coltyp.Long, record=_catalog_column_record(1, "Parent", JET_coltyp.Long))
    )
    child = Table(catalog.esedb, "child", 1, record=_catalog_table_record("child", "parent"))
    child._add_column(
        Column(1, "Child", JET_coltyp.Long, record=_catalog_column_record(1, "Child", JET_coltyp.Long))
    )
    _register(catalog, parent)
    _register(catalog, child)

    with pytest.raises(InvalidDatabase, match="Column identifier conflict for 1"):
        catalog._resolve_template(child)


def test_catalog_duplicate_name_conflict_fails() -> None:
    catalog = _new_catalog()
    parent = Table(catalog.esedb, "parent", 1, record=_catalog_table_record("parent"))
    parent._add_column(
        Column(256, "Dup", JET_coltyp.Binary, record=_catalog_column_record(256, "Dup", JET_coltyp.Binary))
    )
    child = Table(catalog.esedb, "child", 1, record=_catalog_table_record("child", "parent"))
    child._add_column(
        Column(257, "Dup", JET_coltyp.Binary, record=_catalog_column_record(257, "Dup", JET_coltyp.Binary))
    )
    _register(catalog, parent)
    _register(catalog, child)

    with pytest.raises(InvalidDatabase, match="Column name conflict for 'Dup'"):
        catalog._resolve_template(child)


def test_table_without_template_is_unchanged() -> None:
    esedb = _mock_esedb()
    table = Table(esedb, "plain", 1, record=_catalog_table_record("plain"))
    table._add_column(Column(1, "Id", JET_coltyp.Long, record=_catalog_column_record(1, "Id", JET_coltyp.Long)))

    catalog = _new_catalog()
    _register(catalog, table)
    catalog._resolve_template(table)

    assert [column.name for column in table.columns] == ["Id"]
    assert table.column("Id").inherited is False
    assert table.column("Id").offset == 0
