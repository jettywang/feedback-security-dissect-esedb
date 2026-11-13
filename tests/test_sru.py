from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO

import pytest

from dissect.esedb.tools import sru
from dissect.esedb.tools.sru import (
    APP_ID,
    SRU,
    UNDETERMINED,
    USER_ID,
    IdMapping,
    IdRecord,
)


def test_sru(sru_db: BinaryIO) -> None:
    db = SRU(sru_db)

    records = list(db.entries())
    assert len(records) == 220


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def sid(sub_authorities: list[int]) -> bytes:
    return (
        bytes([1, len(sub_authorities)])
        + (5).to_bytes(6, "big")
        + struct.pack(f"<{len(sub_authorities)}I", *sub_authorities)
    )


@dataclass
class FakeRecord:
    """Minimal stand-in for :class:`dissect.esedb.record.Record` using plain Python values."""

    values: dict[str, object]
    _table: FakeTable | None = None

    def get(self, attr: str, raw: bool = False) -> object:
        return self.values.get(attr)


@dataclass
class FakeTable:
    name: str
    _records: list[FakeRecord] = field(default_factory=list)
    column_names: list[str] = field(default_factory=list)

    def records(self) -> list[FakeRecord]:
        return self._records


@dataclass
class FakeEseDB:
    tables_by_name: dict[str, FakeTable]

    def table(self, name: str) -> FakeTable:
        return self.tables_by_name[name]

    def tables(self) -> list[FakeTable]:
        return list(self.tables_by_name.values())


def build_sru(id_map_rows: list[dict[str, object]], provider_rows: dict[str, list[dict]]) -> SRU:
    """Build an :class:`SRU` backed entirely by in-memory fake tables."""
    id_map_table = FakeTable(
        "SruDbIdMapTable",
        [FakeRecord(row) for row in id_map_rows],
        ["IdType", "IdIndex", "IdBlob"],
    )
    providers = {}
    for name, rows in provider_rows.items():
        table = FakeTable(name, [], list(rows[0].keys()) if rows else [])
        table._records = [FakeRecord(row, _table=table) for row in rows]
        providers[name] = table

    fake_db = FakeEseDB({"SruDbIdMapTable": id_map_table, **providers})

    parser = SRU.__new__(SRU)
    parser.esedb = fake_db
    parser.id_map = parser._build_id_map(id_map_table)
    return parser


NETWORK_PROVIDER = sru.NAME_TO_GUID_MAP["sdp_network_provider"]
CPU_PROVIDER = sru.NAME_TO_GUID_MAP["sdp_cpu_provider"]


def make_provider_rows(app_index: int, user_index: int) -> dict[str, list[dict]]:
    """Two providers, each with one small record, sharing the same identity references."""
    return {
        NETWORK_PROVIDER: [
            {
                "AutoIncId": 1,
                "TimeStamp": 0,
                "AppId": app_index,
                "UserId": user_index,
                "BytesInBound": 100,
                "BytesOutBound": 50,
                "BytesTotal": 150,
            }
        ],
        CPU_PROVIDER: [
            {
                "AutoIncId": 1,
                "TimeStamp": 0,
                "AppId": app_index,
                "UserId": user_index,
                "ProcessorTime": 25,
            }
        ],
    }


def test_resolves_utf16_app_and_sid_user() -> None:
    db = build_sru(
        [
            {"IdType": 0, "IdIndex": 1, "IdBlob": utf16("C:\\Windows\\evil.exe")},
            {"IdType": 3, "IdIndex": 2, "IdBlob": sid([21, 1, 2, 3, 500])},
        ],
        make_provider_rows(1, 2),
    )

    app = db.resolve_identity(1, APP_ID)
    assert app.determined
    assert app.status == "C:\\Windows\\evil.exe"
    assert app.errors is None

    user = db.resolve_identity(2, USER_ID)
    assert user.determined
    assert user.status == "S-1-5-21-1-2-3-500"
    assert user.errors is None

    for entry in db.entries():
        assert entry[APP_ID] == "C:\\Windows\\evil.exe"
        assert entry[USER_ID] == "S-1-5-21-1-2-3-500"


def test_duplicate_id_index_conflicting_content_is_undetermined() -> None:
    db = build_sru(
        [
            {"IdType": 0, "IdIndex": 10, "IdBlob": utf16("C:\\Windows\\legit.exe")},
            {"IdType": 0, "IdIndex": 10, "IdBlob": utf16("C:\\Temp\\malware.exe")},
            {"IdType": 3, "IdIndex": 20, "IdBlob": sid([21, 1, 2, 3, 500])},
        ],
        make_provider_rows(10, 20),
    )

    mapping = db.id_map[10]
    assert isinstance(mapping, IdMapping)
    assert len(mapping.records) == 2
    assert mapping.conflicts
    assert all("duplicate IdIndex" in conflict for conflict in mapping.conflicts)

    identity = db.resolve_identity(10, APP_ID)
    assert identity.status == UNDETERMINED
    assert identity.determined is False
    assert any("conflicting identifier values" in error for error in identity.errors)
    # Both candidate values are still available as evidence, nothing was silently picked.
    assert {record.value for record in mapping.records} == {
        "C:\\Windows\\legit.exe",
        "C:\\Temp\\malware.exe",
    }

    # The user mapping is unrelated and must stay determined.
    assert db.resolve_identity(20, USER_ID).status == "S-1-5-21-1-2-3-500"


def test_duplicate_id_index_identical_content_is_not_a_conflict() -> None:
    db = build_sru(
        [
            {"IdType": 0, "IdIndex": 11, "IdBlob": utf16("C:\\Windows\\same.exe")},
            {"IdType": 0, "IdIndex": 11, "IdBlob": utf16("C:\\Windows\\same.exe")},
        ],
        {},
    )

    mapping = db.id_map[11]
    assert len(mapping.records) == 2
    assert mapping.conflicts == []
    assert db.resolve_identity(11, APP_ID).status == "C:\\Windows\\same.exe"


def test_missing_user_mapping_keeps_activity_counts() -> None:
    provider_rows = make_provider_rows(1, 999)
    db = build_sru(
        [
            {"IdType": 0, "IdIndex": 1, "IdBlob": utf16("C:\\Windows\\evil.exe")},
        ],
        provider_rows,
    )

    entries = list(db.entries())
    assert len(entries) == 2

    user_identity = db.resolve_identity(999, USER_ID)
    assert user_identity.status == UNDETERMINED
    assert any("missing IdIndex mapping" in error for error in user_identity.errors)
    assert user_identity.mapping is None

    for entry in entries:
        assert entry.identity(USER_ID).status == UNDETERMINED
        assert entry[APP_ID] == "C:\\Windows\\evil.exe"
        # Counters survive the unresolved user attribution.
        if entry.provider == NETWORK_PROVIDER:
            assert entry["BytesTotal"] == 150
        else:
            assert entry["ProcessorTime"] == 25


def test_missing_id_blob_is_undetermined() -> None:
    db = build_sru(
        [
            {"IdType": 3, "IdIndex": 30, "IdBlob": None},
            {"IdType": 0, "IdIndex": 31, "IdBlob": None},
        ],
        {},
    )

    user = db.resolve_identity(30, USER_ID)
    assert user.status == UNDETERMINED
    assert any("missing IdBlob" in error for error in user.errors)

    app = db.resolve_identity(31, APP_ID)
    assert app.status == UNDETERMINED
    assert any("missing IdBlob" in error for error in app.errors)


def test_truncated_utf16_blob_is_undetermined_but_evidence_kept() -> None:
    db = build_sru(
        [
            # Odd byte length: no terminating code unit for the final UTF-16 character.
            {"IdType": 0, "IdIndex": 40, "IdBlob": b"C\x00:\x00\\\x00x"},
        ],
        {},
    )

    record = db.id_map[40].records[0]
    assert record.error == "truncated UTF-16 IdBlob"
    assert record.value is not None

    identity = db.resolve_identity(40, APP_ID)
    assert identity.status == UNDETERMINED
    assert any("truncated UTF-16 IdBlob" in error for error in identity.errors)


def test_truncated_sid_blob_is_undetermined() -> None:
    truncated_sid = bytes([1, 5]) + (5).to_bytes(6, "big") + struct.pack("<I", 18)
    db = build_sru(
        [
            {"IdType": 3, "IdIndex": 50, "IdBlob": truncated_sid},
        ],
        {},
    )

    record = db.id_map[50].records[0]
    assert record.error is not None
    assert "SID" in record.error

    identity = db.resolve_identity(50, USER_ID)
    assert identity.status == UNDETERMINED
    assert any("SID" in error for error in identity.errors)


def test_non_sid_blob_is_not_treated_as_user_sid() -> None:
    # A UTF-16 application identifier (IdType 4) must never be interpreted as a user SID, even though IdBlob is set.
    db = build_sru(
        [
            {"IdType": 4, "IdIndex": 60, "IdBlob": utf16("Microsoft.Windows.ShellExperienceHost_10.0")},
            # Conversely a SID is not an application identifier.
            {"IdType": 3, "IdIndex": 61, "IdBlob": sid([21, 1, 2, 3, 500])},
        ],
        {},
    )

    assert db.resolve_identity(60, APP_ID).status == "Microsoft.Windows.ShellExperienceHost_10.0"
    wrong_column = db.resolve_identity(60, USER_ID)
    assert wrong_column.status == UNDETERMINED
    assert any("not a valid UserId type" in error for error in wrong_column.errors)

    assert db.resolve_identity(61, USER_ID).status == "S-1-5-21-1-2-3-500"
    assert db.resolve_identity(61, APP_ID).status == UNDETERMINED


def test_unknown_id_type_is_undetermined() -> None:
    db = build_sru(
        [
            {"IdType": 99, "IdIndex": 70, "IdBlob": utf16("whatever")},
        ],
        {},
    )

    record = db.id_map[70].records[0]
    assert record.error == "unknown IdType: 99"
    assert db.resolve_identity(70, APP_ID).status == UNDETERMINED
    assert db.resolve_identity(70, USER_ID).status == UNDETERMINED


def test_conflicting_type_for_same_index_is_undetermined() -> None:
    # Same index used once as an app string and once as a SID: neither column may claim it without evidence.
    db = build_sru(
        [
            {"IdType": 0, "IdIndex": 80, "IdBlob": utf16("C:\\Windows\\app.exe")},
            {"IdType": 3, "IdIndex": 80, "IdBlob": sid([18])},
        ],
        make_provider_rows(80, 80),
    )

    mapping = db.id_map[80]
    assert mapping.conflicts
    assert db.resolve_identity(80, APP_ID).status == UNDETERMINED
    assert db.resolve_identity(80, USER_ID).status == UNDETERMINED

    for entry in db.entries():
        assert entry[APP_ID] == UNDETERMINED
        assert entry[USER_ID] == UNDETERMINED
        # Activity counters remain available despite both identities being undetermined.
        assert entry["AutoIncId"] == 1


def test_entry_repr_shows_attribution_status() -> None:
    db = build_sru(
        [
            {"IdType": 0, "IdIndex": 1, "IdBlob": utf16("C:\\Windows\\evil.exe")},
        ],
        make_provider_rows(1, 999),
    )

    entry = next(db.get_table_entries(table_name=None, table_guid=NETWORK_PROVIDER))
    rendered = repr(entry)
    assert "AppId='C:\\\\Windows\\\\evil.exe'" in rendered
    # The missing user mapping is rendered as an explicit undetermined status, not as the raw index 999.
    assert f"UserId='{UNDETERMINED}'" in rendered
    assert "UserId=999" not in rendered


def test_legacy_resolve_id_behaviour() -> None:
    db = build_sru(
        [
            {"IdType": 0, "IdIndex": 1, "IdBlob": utf16("C:\\Windows\\evil.exe")},
            {"IdType": 3, "IdIndex": 2, "IdBlob": None},
            {"IdType": 0, "IdIndex": 3, "IdBlob": utf16("a")},
            {"IdType": 0, "IdIndex": 3, "IdBlob": utf16("b")},
        ],
        {},
    )

    assert db.resolve_id(1) == "C:\\Windows\\evil.exe"
    # Empty blob and conflicting duplicates return None rather than a guessed identity.
    assert db.resolve_id(2) is None
    assert db.resolve_id(3) is None
    # An index without any mapping row still raises IndexError.
    with pytest.raises(IndexError) as exc_info:
        db.resolve_id(12345)
    assert exc_info.value.args == (12345,)


def test_real_database_preserves_evidence(sru_db: BinaryIO) -> None:
    db = SRU(sru_db)

    # Every mapping exposes its raw rows and the index is preserved.
    for id_index, mapping in db.id_map.items():
        assert isinstance(mapping, IdMapping)
        assert mapping.id_index == id_index
        assert all(isinstance(record, IdRecord) for record in mapping.records)

    # The reference database contains records whose IdBlob is NULL: those identities stay undetermined.
    undetermined = [
        entry
        for entry in db.entries()
        if entry.identity(APP_ID).status == UNDETERMINED or entry.identity(USER_ID).status == UNDETERMINED
    ]
    assert undetermined
    for entry in undetermined:
        assert any(
            "missing IdBlob" in error
            for identity in (entry.identity(APP_ID), entry.identity(USER_ID))
            for error in (identity.errors or [])
        )
