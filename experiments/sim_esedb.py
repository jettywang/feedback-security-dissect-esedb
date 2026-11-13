"""In-memory reproduction of the ESE index keying and exact-lookup semantics.

The goal is to answer a forensic question with fully controlled inputs:

* A textual index stores *normalized sort keys*, not the raw record bytes.
* Exact lookup (``BTree.search(key, exact=True)``) compares those normalized
  keys byte-for-byte (see ``dissect.esedb.btree.find_node``, which documents
  that B-tree key comparison matches Python ``bytes`` comparison 1:1).
* Therefore "exact hit" means *database equivalence of the sort key*, never
  equality of the original string and never Python ``str ==``.

This module deliberately reuses the production encoder
(``dissect.esedb.index.encode_key`` and ``Index.make_key``) so the experiment
exercises the same code path as a real database. Only the storage layer is
simulated: a sorted list of ``(normalized_key, record)`` pairs searched with
``bisect``, which is the byte-order comparison the B-tree performs.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from dissect.esedb.c_esedb import CODEPAGE, JET_coltyp
from dissect.esedb.index import Index, encode_key
from dissect.esedb.lcmapstring import MapFlags

# LCMap flags observed on every text index in the shipped fixtures:
# LCMAP_SORTKEY | NORM_IGNORECASE | NORM_IGNOREWIDTH | NORM_IGNOREKANATYPE
# Note the absence of NORM_IGNORENONSPACE: accents are *not* ignored.
DEFAULT_LCMAP_FLAGS = (
    MapFlags.LCMAP_SORTKEY
    | MapFlags.NORM_IGNORECASE
    | MapFlags.NORM_IGNOREWIDTH
    | MapFlags.NORM_IGNOREKANATYPE
)


@dataclass(frozen=True)
class FakeColumn:
    """Minimal stand-in for ``dissect.esedb.table.Column``.

    Only the attributes touched by :func:`dissect.esedb.index.encode_key` are
    populated, so the production encoder accepts it unchanged.
    """

    name: str
    type: JET_coltyp
    encoding: CODEPAGE | None = None
    is_fixed: bool = False

    @property
    def is_text(self) -> bool:
        return self.type in (JET_coltyp.Text, JET_coltyp.LongText)

    @property
    def is_binary(self) -> bool:
        return self.type in (JET_coltyp.Binary, JET_coltyp.LongBinary)


class _FakeIndexRecord:
    """Answers the catalog ``record.get(...)`` calls made by the encoder."""

    def __init__(self, lcmap_flags: int, locale: str, key_most: int, var_seg_mac: int):
        self._lcmap_flags = lcmap_flags
        self._locale = locale.encode("utf-16-le")
        self._key_most = key_most
        self._var_seg_mac = var_seg_mac

    def get(self, name: str) -> Any:
        if name == "LCMapFlags":
            return self._lcmap_flags
        if name == "LocaleName":
            return self._locale
        if name == "KeyMost":
            return self._key_most
        if name == "VarSegMac":
            return self._var_seg_mac
        raise KeyError(name)


def unicode_column(name: str) -> FakeColumn:
    return FakeColumn(name, JET_coltyp.Text, CODEPAGE.UNICODE)


def ascii_column(name: str) -> FakeColumn:
    return FakeColumn(name, JET_coltyp.Text, CODEPAGE.ASCII)


def long_column(name: str) -> FakeColumn:
    return FakeColumn(name, JET_coltyp.Long, is_fixed=True)


@dataclass
class StoredRecord:
    """A controlled record. ``raw`` keeps the exact on-disk bytes per column."""

    record_id: int
    values: dict[str, Any]
    raw: dict[str, bytes]
    key: bytes = b""
    # Columns carried on the record but *not* part of the index key. These are
    # the "later columns" in the task: equal sort key must not imply they match.
    payload: dict[str, Any] = field(default_factory=dict)


class SimulatedIndex:
    """A sorted store that mirrors the ESE index contract.

    Records are ordered by their normalized key bytes. Lookup is a
    ``bisect`` range scan over those bytes, exactly the comparison the real
    ``BTree`` performs. Duplicate keys are kept adjacent, mirroring ESE's
    guarantee that entries with equal indexed columns are neighbours.
    """

    def __init__(
        self,
        columns: list[FakeColumn],
        lcmap_flags: int = DEFAULT_LCMAP_FLAGS,
        locale: str = "en-US",
        key_most: int = 255,
        var_seg_mac: int | None = None,
    ):
        self.columns = columns
        self.key_most = key_most
        # A real Index reads KeyMost/VarSegMac from its catalog record.
        self._index = SimpleNamespace(
            record=_FakeIndexRecord(lcmap_flags, locale, key_most, var_seg_mac or key_most),
            _key_most=key_most,
            _var_seg_mac=var_seg_mac or key_most,
            columns=columns,
        )
        # Bind the unbound production method to our namespace.
        self._index.make_key = lambda values: Index.make_key(self._index, values)
        self._records: list[StoredRecord] = []
        self._keys: list[bytes] = []

    def make_key(self, values: dict[str, Any]) -> bytes:
        return self._index.make_key(values)

    def encode_column(self, column: FakeColumn, value: Any) -> bytes:
        return encode_key(self._index, column, value, self._index._var_seg_mac)

    def insert(self, record_id: int, values: dict[str, Any], raw: dict[str, bytes],
               payload: dict[str, Any] | None = None) -> StoredRecord:
        key = self.make_key(values)
        record = StoredRecord(record_id, dict(values), dict(raw), key, dict(payload or {}))
        pos = bisect.bisect_left(self._keys, key)
        self._keys.insert(pos, key)
        self._records.insert(pos, record)
        return record

    def exact_search(self, values: dict[str, Any]) -> list[StoredRecord]:
        """Return every record whose normalized key equals the query key.

        This is the ``exact=True`` contract: equality of normalized key bytes,
        which is the database equivalence relation, not Python ``str ==``.
        """
        key = self.make_key(values)
        lo = bisect.bisect_left(self._keys, key)
        hi = bisect.bisect_right(self._keys, key)
        return list(self._records[lo:hi])

    def records(self) -> list[StoredRecord]:
        return list(self._records)


def utf16(value: str) -> bytes:
    """The raw storage encoding of a Unicode (code page 1200) text column."""
    return value.encode("utf-16-le")


def ascii_bytes(value: str) -> bytes:
    """The raw storage encoding of an ASCII/Western text column."""
    return value.encode("cp1252", errors="backslashreplace")
