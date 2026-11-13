from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.sid import read_sid
from dissect.util.ts import oatimestamp, wintimestamp

from dissect.esedb.esedb import EseDB
from dissect.esedb.record import Record, serialise_record_column_values

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.esedb.c_esedb import RecordValue
    from dissect.esedb.table import Table

NATIVE_TYPE_MAP = {
    "{DD6636C4-8929-4683-974E-22C046A43763}": {"ConnectStartTime": wintimestamp},
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": {"EndTime": wintimestamp},
}

SKIP_TABLES = [
    "MSysObjects",
    "MSysObjectsShadow",
    "MSysObjids",
    "MSysLocales",
    "SruDbIdMapTable",
    "SruDbCheckpointTable",
]

# ``SruDbIdMapTable.IdType`` discriminates the kind of identifier stored in ``IdBlob``.
# The application providers reference the UTF-16 string types, while ``UserId`` columns reference the SID type.
# These values are derived from the on-disk data: every non-null ``AppId`` reference resolves to one of the string
# types (0, 2, 4), while every non-null ``UserId`` reference resolves to the SID type (3).
ID_TYPE_SID = 3
ID_TYPE_STRING = frozenset((0, 1, 2, 4))

# Columns that carry an identity reference and the identifier type that is valid for them.
APP_ID = "AppId"
USER_ID = "UserId"
IDENTITY_COLUMNS = {APP_ID, USER_ID}
EXPECTED_ID_TYPES = {
    APP_ID: ID_TYPE_STRING,
    USER_ID: frozenset((ID_TYPE_SID,)),
}

# Sentinel for an identity that cannot be attributed to a single, type-correct value.
UNDETERMINED = "<undetermined>"


NAME_TO_GUID_MAP = {
    "network_data": "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
    "network_connectivity": "{DD6636C4-8929-4683-974E-22C046A43763}",
    "energy_estimator": "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}",
    "energy_usage": "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
    "energy_usage_lt": "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT",
    "application": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
    "push_notifications": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}",
    "application_timeline": "{5C8CF1C7-7257-4F13-B223-970EF5939312}",
    "vfu": "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}",
    # Refs:
    # - http://dfir.pro/index.php?link_id=92259 and
    # - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions
    "sdp_volume_provider": "{17F4D97B-F26A-5E79-3A82-90040A47D13D}",
    "sdp_physical_disk_provider": "{841A7317-3805-518B-C2EA-AD224CB4AF84}",
    "sdp_cpu_provider": "{DC3D3B50-BB90-5066-FA4E-A5F90DD8B677}",
    "sdp_network_provider": "{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}",
    # not seen in the wild
    "sdp_perf_count_provider": "{38AD6548-9313-58F8-45C7-D293BAFDC879}",
    "sdp_event_log_provider": "{CDF8EBF6-7C0F-5AC2-158F-DBFBEE981152}",
}


class SRU:
    def __init__(self, fh: BinaryIO):
        self.esedb = EseDB(fh)

        id_map_table = self.esedb.table("SruDbIdMapTable")
        self.id_map = self._build_id_map(id_map_table)

    def _build_id_map(self, id_map_table: Table) -> dict[int, IdMapping]:
        """Index every ``SruDbIdMapTable`` row by ``IdIndex`` without discarding duplicates.

        A single ``IdIndex`` may occur more than once with different ``IdType``/``IdBlob`` values. Such conflicts are
        preserved on the resulting :class:`IdMapping` instead of one row silently overwriting another.
        """
        id_map: dict[int, IdMapping] = {}
        for record in id_map_table.records():
            id_index = record.get("IdIndex")
            id_type = record.get("IdType")
            id_blob = record.get("IdBlob")
            if isinstance(id_blob, memoryview):
                id_blob = id_blob.tobytes()

            mapping = id_map.get(id_index)
            if mapping is None:
                mapping = IdMapping(id_index=id_index)
                id_map[id_index] = mapping

            value, error = self._decode_blob(id_type, id_blob)
            mapping.records.append(IdRecord(id_type=id_type, id_blob=id_blob, value=value, error=error))

        for mapping in id_map.values():
            mapping.conflicts = mapping._detect_conflicts()

        return id_map

    @staticmethod
    def _decode_blob(id_type: int | None, id_blob: bytes | None) -> tuple[str | None, str | None]:
        """Interpret an ``IdBlob`` according to its ``IdType``.

        Returns a ``(value, error)`` tuple. ``error`` is set when the blob is missing, truncated or cannot be parsed
        as the identifier type claims, while a best-effort ``value`` is still returned when possible.
        """
        if id_blob is None:
            return None, "missing IdBlob"

        if id_type in ID_TYPE_STRING:
            if len(id_blob) % 2:
                return id_blob.decode("utf-16-le", errors="replace").rstrip("\x00"), "truncated UTF-16 IdBlob"
            return id_blob.decode("utf-16-le", errors="replace").rstrip("\x00"), None

        if id_type == ID_TYPE_SID:
            try:
                value = read_sid(id_blob)
            except Exception as e:
                return None, f"unparseable SID IdBlob: {e}"
            if not value:
                return None, "truncated SID IdBlob"
            return value, None

        return None, f"unknown IdType: {id_type}"

    def get_table(self, table_name: str | None = None, table_guid: str | None = None) -> Table | None:
        if all((table_name, table_guid)) or not any((table_name, table_guid)):
            raise ValueError("Either table_name or table_guid must be provided")

        if table_name and table_name not in NAME_TO_GUID_MAP:
            raise ValueError(f"Unknown table name: {table_name}")

        table_guid = table_guid or NAME_TO_GUID_MAP[table_name]

        try:
            return self.esedb.table(table_guid)
        except KeyError:
            return None

    def entries(self) -> Iterator[Entry]:
        for t in self.esedb.tables():
            if t.name in SKIP_TABLES:
                continue
            yield from self.get_table_entries(table=t)

    __iter__ = entries

    def get_table_entries(
        self, table: Table = None, table_name: str | None = None, table_guid: str | None = None
    ) -> Iterator[Entry]:
        table = table or self.get_table(table_name=table_name, table_guid=table_guid)
        if not table:
            return
        for record in table.records():
            yield Entry(self, table, record)

    def resolve_identity(self, value: int, column: str) -> Identity:
        """Resolve an ``AppId``/``UserId`` reference, preserving every conflicting or malformed mapping.

        The identifier is only attributed when exactly one type-correct, parseable value exists. Missing indices,
        duplicate indices, truncated blobs and references whose ``IdType`` does not fit the column all produce an
        :class:`Identity` whose status is :data:`UNDETERMINED`, together with the evidence explaining why.
        """
        mapping = self.id_map.get(value)
        if mapping is None:
            return Identity(
                index=value,
                column=column,
                status=UNDETERMINED,
                errors=[f"missing IdIndex mapping: {value}"],
            )

        expected_types = EXPECTED_ID_TYPES[column]
        errors = list(mapping.conflicts)

        candidates = []
        for id_record in mapping.records:
            if id_record.id_type not in expected_types:
                errors.append(
                    f"IdType {id_record.id_type} is not a valid {column} type "
                    f"(expected one of {sorted(expected_types)})"
                )
                continue
            if id_record.error:
                errors.append(id_record.error)
                continue
            candidates.append(id_record)

        distinct_values = {candidate.value for candidate in candidates}
        # A conflicting IdIndex (duplicate rows with different IdType/IdBlob) can never be safely attributed,
        # even if one of the rows happens to fit the column. The analyst must inspect the evidence instead.
        if not mapping.conflicts and len(distinct_values) == 1:
            return Identity(
                index=value,
                column=column,
                status=next(iter(distinct_values)),
                mapping=mapping,
                errors=errors or None,
            )

        if len(distinct_values) > 1:
            errors.append("conflicting identifier values for IdIndex %d" % value)

        return Identity(
            index=value,
            column=column,
            status=UNDETERMINED,
            mapping=mapping,
            errors=errors or None,
        )

    def resolve_id(self, value: int) -> str | None:
        """Backwards-compatible identifier lookup.

        Mirrors :meth:`resolve_identity` but returns the attributed string, ``None`` for an empty/undetermined
        identity, and raises :class:`IndexError` for an index that has no mapping row at all.
        """
        mapping = self.id_map.get(value)
        if mapping is None:
            raise IndexError(value)

        identity = self.resolve_identity(value, APP_ID)
        if identity.status == UNDETERMINED:
            return None
        return identity.status


@dataclass
class IdRecord:
    """A single raw row of ``SruDbIdMapTable`` for a given ``IdIndex``."""

    id_type: int | None
    id_blob: bytes | None
    value: str | None
    error: str | None = None


@dataclass
class IdMapping:
    """All ``SruDbIdMapTable`` rows sharing one ``IdIndex``, including duplicate/conflicting evidence."""

    id_index: int | None
    records: list[IdRecord] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def _detect_conflicts(self) -> list[str]:
        conflicts = []
        if len(self.records) > 1:
            type_signatures = {(record.id_type, record.id_blob) for record in self.records}
            if len(type_signatures) > 1:
                conflicts.append(f"duplicate IdIndex {self.id_index} with conflicting IdType/IdBlob")
        return conflicts


@dataclass
class Identity:
    """The resolved attribution of an ``AppId``/``UserId`` reference, with full evidence."""

    index: int | None
    column: str
    status: str
    mapping: IdMapping | None = None
    errors: list[str] | None = None

    @property
    def determined(self) -> bool:
        return self.status != UNDETERMINED

    def __str__(self) -> str:
        return self.status


class Entry:
    def __init__(self, sru: SRU, table: Table, record: Record):
        self.sru = sru
        self.table = table
        self.record = record
        self.provider = table.name

    def identity(self, attr: str) -> Identity:
        """Return the full :class:`Identity` (attribution plus evidence) for an ``AppId``/``UserId`` reference."""
        index = self.record.get(attr)
        return self.sru.resolve_identity(index, attr)

    def _get(self, attr: str) -> RecordValue:
        value = self.record.get(attr)
        if value is None:
            return value

        if attr in IDENTITY_COLUMNS:
            value = self.identity(attr).status

        if attr == "TimeStamp":
            value = oatimestamp(value)

        type_map = NATIVE_TYPE_MAP.get(self.table.name, None)
        if type_map and attr in type_map:
            value = type_map[attr](value)

        # Application timeline ({5C8CF1C7-7257-4F13-B223-970EF5939312}) seems to have a weird null value
        # (******** in decimal)
        if self.table.name == "{5C8CF1C7-7257-4F13-B223-970EF5939312}" and value in (0x2A2A2A2A2A2A2A2A, 0x2A2A2A2A):
            value = None

        return value

    def __getitem__(self, attr: str) -> RecordValue:
        return self._get(attr)

    def __getattr__(self, attr: str) -> RecordValue:
        try:
            return self._get(attr)
        except Exception:
            return object.__getattribute__(self, attr)

    def __repr__(self) -> str:
        # Render the stored columns, but substitute the raw AppId/UserId index with its attributed value so an
        # undetermined identity is visible instead of looking like a valid numeric reference.
        column_values = serialise_record_column_values(self.record)
        for attr in IDENTITY_COLUMNS:
            if attr in self.table.column_names and self.record.get(attr) is not None:
                column_values = column_values.replace(
                    f"{attr}={self.record.get(attr)!r}", f"{attr}={self._get(attr)!r}", 1
                )
        return f"<Entry provider={self.table.name!r} {column_values}>"


def main() -> None:
    parser = argparse.ArgumentParser(description="dissect.esedb SRU parser")
    parser.add_argument("input", help="SRU database to read")
    parser.add_argument("-p", "--provider", help="filter records from this provider")
    args = parser.parse_args()

    with Path(args.input).open("rb") as fh:
        parser = SRU(fh)

        if args.provider in NAME_TO_GUID_MAP:
            for e in parser.get_table_entries(table_name=args.provider):
                print(e)
        elif args.provider:
            for e in parser.get_table_entries(table_guid=args.provider):
                print(e)
        else:
            for e in parser.entries():
                print(e)


if __name__ == "__main__":
    main()
