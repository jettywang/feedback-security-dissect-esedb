from __future__ import annotations

import struct
from functools import cached_property
from typing import TYPE_CHECKING, Any

from dissect.esedb import compression
from dissect.esedb.btree import BTree
from dissect.esedb.c_esedb import (
    CODEPAGE,
    COLUMN_TYPE_MAP,
    COMPRESSION_SCHEME,
    SYSOBJ,
    TAG_FLAG,
    ColumnType,
    JET_coltyp,
    RecordValue,
)
from dissect.esedb.exceptions import LongValueError, NoNeighbourPageError
from dissect.esedb.index import Index
from dissect.esedb.record import Record

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.esedb.cursor import Cursor
    from dissect.esedb.esedb import EseDB
    from dissect.esedb.page import Page


class LongValueChunk:
    """Evidence of a single long value chunk as it was read from the database.

    Attributes:
        key: The full B-tree key of the chunk, including the value identifier and chunk offset.
        offset: The logical offset of the chunk within the long value, decoded from the key.
        data: The raw chunk data as stored on the page.
        page: The logical page number the chunk was read from.
        tag: The tag number on that page.
        node: The node index on that page.
        length: The stored length of the raw chunk data.
        tag_flags: The tag flags of the chunk node, including whether the page marked it compressed.
        decompressed_size: The validated logical size of the chunk after decompression.
        compression: The compression scheme used for this chunk, or ``None`` if not yet known.
        value: The logical bytes of the chunk after any decompression, or ``None`` if not yet known.
    """

    __slots__ = (
        "compression",
        "data",
        "decompressed_size",
        "key",
        "length",
        "node",
        "offset",
        "page",
        "tag",
        "tag_flags",
        "value",
    )

    def __init__(
        self,
        key: bytes,
        offset: int,
        data: bytes,
        page: int,
        tag: int,
        node: int,
        tag_flags: TAG_FLAG,
    ):
        self.key = key
        self.offset = offset
        self.data = data
        self.page = page
        self.tag = tag
        self.node = node
        self.tag_flags = tag_flags
        self.length = len(data)

        self.decompressed_size = None
        self.compression = None
        self.value = None

    def __repr__(self) -> str:
        return (
            f"<LongValueChunk offset={self.offset} length={self.length} "
            f"page={self.page} tag={self.tag} compression={self.compression}>"
        )


class Table:
    """Represents a table in an ESE database.

    Contains all the relevant metadata of the table, as well as all columns and indices that have been added
    by the catalog.

    Args:
        esedb: An instance of :class:`~dissect.esedb.esedb.EseDB`.
        name: The table name.
        root_page: The root page of the table.
        columns: A list of :class:`Column` for this table.
        indexes: A list of :class:`~dissect.esedb.index.Index` for this table.
        record: The :class:`~dissect.esedb.record.Record` of this table from the catalog table.
    """

    def __init__(
        self,
        esedb: EseDB,
        name: str,
        root_page: int,
        columns: list[Column] | None = None,
        indexes: list[Index] | None = None,
        record: Record = None,
    ):
        self.esedb = esedb

        self._column_name_map: dict[str, Column] = {}
        self._column_id_map: dict[int, Column] = {}
        self._index_name_map: dict[str, Index] = {}

        self.name = name
        self.root_page = root_page
        self.columns: list[Column] = []
        self.indexes: list[Index] = []

        # Set by the catalog during parsing
        self._long_value_record: Record = None
        self._long_callback_record: Record = None

        self._fixed_value_offset = 0

        columns = columns or []
        for column in columns:
            self._add_column(column)

        indexes = indexes or []
        for index in indexes:
            self._add_index(index)

        self.record = record

    def __repr__(self) -> str:
        return f"<Table name={self.name!r}>"

    @cached_property
    def root(self) -> Page:
        """Return the root page of the table."""
        return self.esedb.page(self.root_page)

    @cached_property
    def lv_page(self) -> Page:
        """Return the long value page of the table.

        Raises:
            TypeError: If the table has no long values.
        """
        if not self._long_value_record:
            raise TypeError(f"Table has no long values: {self.name}")

        return self.esedb.page(self._long_value_record.get("ColtypOrPgnoFDP"))

    def column(self, name: str) -> Column:
        """Return the column with the given name.

        Args:
            name: The name of the column to return.

        Raises:
            KeyError: If no column with the given name exists.
        """
        try:
            return self._column_name_map[name]
        except KeyError:
            raise KeyError(f"No column with this name in table {self.name}: {name}")

    @property
    def column_names(self) -> list[str]:
        """Return a list of all the column names."""
        return list(self._column_name_map.keys())

    @property
    def primary_index(self) -> Index | None:
        # It's generally the first index, but loop just in case
        for index in self.indexes:
            if index.is_primary:
                return index
        return None

    def cursor(self) -> Cursor | None:
        """Create a new cursor for this table."""
        primary_idx = self.primary_index
        if primary_idx:
            return primary_idx.cursor()
        return None

    def index(self, name: str) -> Index:
        """Return the index with the given ``name``.

        Args:
            name: The name of the index to return.

        Raises:
            KeyError: If no index with the given name exists.
        """
        try:
            return self._index_name_map[name]
        except KeyError:
            raise KeyError(f"No index with this name in table {self.name}: {name}")

    def find_index(self, column_names: list[str]) -> Index | None:
        """Find the most suitable index to search for the given columns.

        Args:
            column_names: A list of column names to find the best index for.
        """
        best_match = 0
        best_index = None
        for index in self.indexes:
            # We want to find the index that has the most matching columns in the order they are indexed
            i = 0
            for column in index.columns:
                if column.name not in column_names:
                    break
                i += 1

            if i > best_match:
                best_index = index
                best_match = i

        return best_index

    def search(self, **kwargs: RecordValue) -> Record | None:
        """Search for a record in the table.

        Args:
            **kwargs: The columns and values to search for.

        Returns:
            The first record that matches the search criteria, or ``None`` if no record was found.
        """
        return self.cursor().search(**kwargs)

    def records(self) -> Iterator[Record]:
        """Return an iterator of all the records of the table."""
        for node in self.root.iter_leaf_nodes():
            yield Record(self, node)

    def get_long_value(self, key: bytes) -> bytes:
        """Retrieve a value from the long value page of the table.

        The value is stored as a contiguous sequence of chunks. Each chunk key extends the (reversed)
        lookup key with a big-endian start offset of the chunk within the logical value. Chunks are
        only accepted when they belong to this exact value, are strictly ordered and cover the
        declared length without gaps or overlaps. A chunk is considered compressed only when its
        stored length differs from the expected logical length *and* its data advertises a supported
        compression scheme.

        Args:
            key: The lookup key for the long value.

        Raises:
            LongValueError: If the value is incomplete, overlapping, out of order, contains foreign
                chunks or does not match the declared length. The exception carries the evidence of
                every chunk that was read, including page and tag numbers.
        """
        return self.get_long_value_chunks(key)[0]

    def get_long_value_chunks(self, key: bytes) -> tuple[bytes, list[LongValueChunk]]:
        """Retrieve a long value together with the evidence of the chunks it was assembled from.

        This is equivalent to :meth:`get_long_value`, but also returns :class:`LongValueChunk`
        instances describing every chunk that contributed to the result, including its key, offset,
        page, tag and compression state.

        Args:
            key: The lookup key for the long value.

        Raises:
            LongValueError: If the value cannot be assembled unambiguously.
        """
        chunks = []
        data = self._get_long_value(key, chunks)
        return data, chunks

    def _get_long_value(self, key: bytes, chunks: list[LongValueChunk]) -> bytes:
        rkey = key[::-1]
        btree = BTree(self.esedb, self.lv_page)
        header = btree.search(rkey)

        if len(header.data) < 8:
            raise LongValueError(
                "Long value header is too small to contain an identifier and declared size",
                key=key,
                evidence=chunks,
            )

        _, size = struct.unpack("<2I", header.data)

        if size == 0:
            return b""

        self._collect_long_value_chunks(key, rkey, size, btree, chunks)

        buf = []
        offset = 0
        for i, chunk in enumerate(chunks):
            if chunk.offset != offset:
                expected = "start" if i == 0 else f"offset {offset}"
                raise LongValueError(
                    f"Long value chunk is out of order or has a gap: chunk offset {chunk.offset} "
                    f"does not match {expected}",
                    key=key,
                    declared_size=size,
                    chunk=chunk,
                    evidence=chunks[: i + 1],
                )

            next_offset = chunks[i + 1].offset if i + 1 < len(chunks) else size
            expected_size = next_offset - chunk.offset

            chunk.decompressed_size = expected_size
            if chunk.length == expected_size:
                # A matching stored length is authoritative, even if the first byte happens to look
                # like a compression scheme identifier.
                chunk.compression = COMPRESSION_SCHEME.COMPRESS_NONE
                chunk.value = chunk.data
                buf.append(chunk.data)
            else:
                chunk, data = self._decompress_long_value_chunk(
                    key, size, chunk, expected_size, chunks[: i + 1], has_next=i + 1 < len(chunks)
                )
                buf.append(data)

            offset = next_offset

        data = b"".join(buf)
        if len(data) != size:
            raise LongValueError(
                f"Long value length mismatch: assembled {len(data)} bytes, header declares {size}",
                key=key,
                declared_size=size,
                evidence=chunks,
            )

        return data

    def _collect_long_value_chunks(
        self, key: bytes, rkey: bytes, size: int, btree: BTree, chunks: list[LongValueChunk]
    ) -> None:
        """Collect and validate the chunk sequence for a single long value."""
        previous_offset = -1

        while True:
            try:
                node = btree.next()
            except NoNeighbourPageError:
                break

            if not node.key.startswith(rkey):
                # Reached the header or chunks of the next long value, stop before mixing them in.
                break

            chunk = LongValueChunk(
                key=bytes(node.key),
                offset=struct.unpack(">I", node.key[-4:])[0] if len(node.key) >= len(rkey) + 4 else -1,
                data=bytes(node.data),
                page=node.tag.page.num,
                tag=node.tag.num,
                node=node.num,
                tag_flags=node.tag.flags,
            )

            if len(node.key) == len(rkey):
                raise LongValueError(
                    "Duplicate long value header encountered while reading chunks",
                    key=key,
                    declared_size=size,
                    chunk=chunk,
                    evidence=[*chunks, chunk],
                )

            if len(node.key) != len(rkey) + 4:
                raise LongValueError(
                    f"Malformed long value chunk key: expected {len(rkey) + 4} bytes, got {len(node.key)}",
                    key=key,
                    declared_size=size,
                    chunk=chunk,
                    evidence=[*chunks, chunk],
                )

            if chunk.offset >= size:
                raise LongValueError(
                    f"Long value chunk offset {chunk.offset} exceeds declared size {size}",
                    key=key,
                    declared_size=size,
                    chunk=chunk,
                    evidence=[*chunks, chunk],
                )

            if chunk.offset <= previous_offset:
                raise LongValueError(
                    f"Duplicate or out of order long value chunk offset {chunk.offset} "
                    f"(previous offset {previous_offset})",
                    key=key,
                    declared_size=size,
                    chunk=chunk,
                    evidence=[*chunks, chunk],
                )

            if chunk.length == 0:
                raise LongValueError(
                    "Empty long value chunk encountered",
                    key=key,
                    declared_size=size,
                    chunk=chunk,
                    evidence=[*chunks, chunk],
                )

            chunks.append(chunk)
            previous_offset = chunk.offset

        if not chunks:
            raise LongValueError(
                f"Long value declares {size} bytes but has no chunks",
                key=key,
                declared_size=size,
                evidence=[],
            )

        if chunks[0].offset != 0:
            raise LongValueError(
                f"Long value is missing its first chunk: first chunk starts at offset {chunks[0].offset}",
                key=key,
                declared_size=size,
                chunk=chunks[0],
                evidence=chunks,
            )

        # At this point only the offsets are known. A chunk that is shorter than the distance to the
        # next chunk is ambiguous: it is either compressed or truncated, which is resolved during
        # assembly. A chunk that is longer, however, unconditionally overlaps its neighbour (or the
        # declared end of the value) and can never be valid.
        for i, current in enumerate(chunks):
            next_offset = chunks[i + 1].offset if i + 1 < len(chunks) else size
            if current.length > next_offset - current.offset:
                raise LongValueError(
                    f"Long value chunk at offset {current.offset} is {current.length} bytes long but "
                    f"ends at offset {next_offset}, causing an overlap",
                    key=key,
                    declared_size=size,
                    chunk=current,
                    evidence=chunks[: i + 1],
                )

    def _decompress_long_value_chunk(
        self,
        key: bytes,
        size: int,
        chunk: LongValueChunk,
        expected_size: int,
        evidence: list[LongValueChunk],
        has_next: bool,
    ) -> tuple[LongValueChunk, bytes]:
        """Decompress a chunk after verifying that it actually advertises a compression scheme."""
        try:
            scheme = compression.scheme(chunk.data)
        except ValueError as e:
            raise LongValueError(
                f"Long value chunk length {chunk.length} does not match expected size {expected_size} "
                "and does not advertise a known compression scheme",
                key=key,
                declared_size=size,
                chunk=chunk,
                evidence=evidence,
            ) from e

        if scheme is None:
            if has_next and chunk.length < expected_size:
                raise LongValueError(
                    f"Long value chunk at offset {chunk.offset} is {chunk.length} bytes but the next chunk "
                    f"starts at offset {chunk.offset + expected_size}, leaving a gap of "
                    f"{expected_size - chunk.length} bytes",
                    key=key,
                    declared_size=size,
                    chunk=chunk,
                    evidence=evidence,
                )

            raise LongValueError(
                f"Long value chunk length {chunk.length} does not match expected size {expected_size} "
                "but is not compressed",
                key=key,
                declared_size=size,
                chunk=chunk,
                evidence=evidence,
            )

        if scheme == COMPRESSION_SCHEME.COMPRESS_SCRUB:
            raise LongValueError(
                f"Long value chunk at offset {chunk.offset} advertises the unsupported SCRUB compression scheme",
                key=key,
                declared_size=size,
                chunk=chunk,
                evidence=evidence,
            )

        if scheme in (COMPRESSION_SCHEME.COMPRESS_XPRESS9, COMPRESSION_SCHEME.COMPRESS_XPRESS10):
            raise NotImplementedError(f"Compression not yet implemented: {scheme}")

        try:
            data = compression.decompress(chunk.data)
        except Exception as e:
            raise LongValueError(
                f"Failed to decompress long value chunk ({scheme}): {e}",
                key=key,
                declared_size=size,
                chunk=chunk,
                evidence=evidence,
            ) from e

        if len(data) != expected_size:
            raise LongValueError(
                f"Decompressed long value chunk ({scheme}) is {len(data)} bytes, expected {expected_size}",
                key=key,
                declared_size=size,
                chunk=chunk,
                evidence=evidence,
            )

        chunk.compression = scheme
        chunk.value = data
        return chunk, data

    def _add_column(self, column: Column) -> None:
        """Add a column to the table."""
        self.columns.append(column)
        self._column_name_map[column.name] = column
        self._column_id_map[column.identifier] = column

        # Precalculate fixed value offsets
        if column.identifier < 128:
            column._offset = self._fixed_value_offset
            self._fixed_value_offset += column.size

    def _add_index(self, index: Index) -> None:
        """Add an index to the table."""
        self.indexes.append(index)
        self._index_name_map[index.name] = index


class Column:
    def __init__(self, identifier: int, name: str, type_: JET_coltyp, record: Record | None = None):
        self.identifier = identifier
        self.name = name
        self.type = type_

        # Set by the table when added, only relevant for fixed value columns
        self._offset = None

        self.record = record

    def __repr__(self) -> str:
        return f"<Column name={self.name!r} identifier={self.identifier:#x} type={self.type} size={self.size}>"

    @property
    def offset(self) -> int:
        return self._offset

    @cached_property
    def is_fixed(self) -> bool:
        return self.identifier <= 127

    @cached_property
    def is_variable(self) -> bool:
        return 127 < self.identifier <= 255

    @cached_property
    def is_tagged(self) -> bool:
        return self.identifier > 255

    @cached_property
    def is_text(self) -> bool:
        return self.type in (JET_coltyp.Text, JET_coltyp.LongText)

    @cached_property
    def is_binary(self) -> bool:
        return self.type in (JET_coltyp.Binary, JET_coltyp.LongBinary)

    @cached_property
    def size(self) -> int:
        if self.record and self.record.get("SpaceUsage"):
            return self.record.get("SpaceUsage")
        return self.ctype.size

    @cached_property
    def default(self) -> Any | None:
        if self.record and self.record.get("DefaultValue"):
            return self.record.get("DefaultValue")
        return None

    @cached_property
    def encoding(self) -> CODEPAGE | None:
        if self.is_text:
            return CODEPAGE(self.record.get("PagesOrLocale")) if self.record else CODEPAGE.ASCII
        return None

    @cached_property
    def ctype(self) -> ColumnType:
        return COLUMN_TYPE_MAP[self.type.value]


class Catalog:
    """Parse and interact with the catalog table.

    The catalog is a special table that contains the metadata for all the other tables in the database.

    Args:
        esedb: An instance of :class:`~dissect.esedb.esedb.EseDB`.
        root_page: The root page of the catalog table.
    """

    CATALOG_COLUMNS = (
        Column(1, "ObjidTable", JET_coltyp.Long),
        Column(2, "Type", JET_coltyp.Short),
        Column(3, "Id", JET_coltyp.Long),
        Column(4, "ColtypOrPgnoFDP", JET_coltyp.Long),
        Column(5, "SpaceUsage", JET_coltyp.Long),
        Column(6, "Flags", JET_coltyp.Long),
        Column(7, "PagesOrLocale", JET_coltyp.Long),
        Column(8, "RootFlag", JET_coltyp.Bit),
        Column(9, "RecordOffset", JET_coltyp.Short),
        Column(10, "LCMapFlags", JET_coltyp.Long),
        Column(11, "KeyMost", JET_coltyp.UnsignedShort),
        Column(12, "LVChunkMax", JET_coltyp.Long),
        Column(128, "Name", JET_coltyp.Text),
        Column(129, "Stats", JET_coltyp.Binary),
        Column(130, "TemplateTable", JET_coltyp.Text),
        Column(131, "DefaultValue", JET_coltyp.Binary),
        Column(132, "KeyFldIDs", JET_coltyp.Binary),
        Column(133, "VarSegMac", JET_coltyp.Binary),
        Column(134, "ConditionalColumns", JET_coltyp.Binary),
        Column(135, "TupleLimits", JET_coltyp.Binary),
        Column(136, "Version", JET_coltyp.Binary),
        Column(137, "SortID", JET_coltyp.Binary),
        Column(256, "CallbackData", JET_coltyp.LongBinary),
        Column(257, "CallbackDependencies", JET_coltyp.LongBinary),
        Column(258, "SeparateLV", JET_coltyp.LongBinary),
        Column(259, "SpaceHints", JET_coltyp.LongBinary),
        Column(260, "SpaceDeferredLVHints", JET_coltyp.LongBinary),
        Column(261, "LocaleName", JET_coltyp.LongBinary),
    )

    def __init__(self, esedb: EseDB, root_page: Page):
        self.esedb = esedb
        self.root_page = root_page
        self.tables = []
        self._table_name_map = {}

        # Create a dummy table with a preset list of columns
        self._ctable = Table(esedb, None, root_page, columns=self.CATALOG_COLUMNS)

        cur_table = None
        for rec in self._ctable.records():
            rtype = rec.get("Type")
            if rtype == SYSOBJ.Table:
                cur_table = Table(self.esedb, rec.get("Name"), rec.get("ColtypOrPgnoFDP"), record=rec)
                self.tables.append(cur_table)
                self._table_name_map[rec.get("Name")] = cur_table

            elif rtype == SYSOBJ.Column:
                column = Column(rec.get("Id"), rec.get("Name"), JET_coltyp(rec.get("ColtypOrPgnoFDP")), record=rec)
                cur_table._add_column(column)

            elif rtype == SYSOBJ.Index:
                index = Index(cur_table, record=rec)
                cur_table._add_index(index)

            elif rtype == SYSOBJ.LongValue:
                cur_table._long_value_record = rec

            elif rtype == SYSOBJ.Callback:
                cur_table._long_callback_record = rec

    def table(self, name: str) -> Table:
        """Retrieve the table with the given name.

        Args:
            name: The table to retrieve.

        Raises:
            KeyError: If no table with that name exists.
        """
        try:
            return self._table_name_map[name]
        except KeyError:
            raise KeyError(f"No table with name: {name}")
