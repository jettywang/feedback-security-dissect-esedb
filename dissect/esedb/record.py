from __future__ import annotations

import enum
import functools
import struct
from binascii import hexlify
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any, NamedTuple

from dissect.util.xmemoryview import xmemoryview

from dissect.esedb import compression
from dissect.esedb.c_esedb import PAGE_FLAG, TAGFLD_HEADER, RecordValue, c_esedb

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.esedb.page import Node
    from dissect.esedb.table import Column, Table


def noop(value: Any) -> Any:
    return value


class ValueSource(enum.Enum):
    """The source of a record field value.

    Allows distinguishing between values that look the same when displayed, but have different on-disk evidence.

    Attributes:
        STORED: The value is physically stored in the record.
        EMPTY: The value is physically stored in the record as zero-length data.
        NULL: The value is explicitly stored as NULL in the record.
        DEFAULT: The value is not stored in the record, the column default is used instead.
        MISSING: The value is not stored in the record and the column has no default.
        CORRUPT: The value is stored in the record but could not be parsed.
    """

    STORED = "stored"
    EMPTY = "empty"
    NULL = "null"
    DEFAULT = "default"
    MISSING = "missing"
    CORRUPT = "corrupt"

    def __str__(self) -> str:
        return self.value


@dataclass
class FieldInfo:
    """Provenance information about the value of a single column in a record.

    Both the raw and the parsed interpretation of the value are derived from the same source determination,
    so they are always consistent with each other and with what :meth:`Record.get` returns.

    Attributes:
        column: The column definition this value belongs to.
        source: The source of the value.
        value: The parsed value, identical to what :meth:`Record.get` returns.
        raw: The raw data as stored, identical to what ``Record.get(raw=True)`` returns.
        offset: The offset of the value within the record data, or ``None`` if it's not stored in the record.
        size: The size of the value within the record data, or ``None`` if it's not stored in the record.
        tag_field: The :class:`TagField` of the value if it's a tagged column, ``None`` otherwise.
        error: The parse error if the source is :attr:`ValueSource.CORRUPT`, ``None`` otherwise.
    """

    column: Column
    source: ValueSource
    value: RecordValue
    raw: bytes | None
    offset: int | None
    size: int | None
    tag_field: TagField | None = field(default=None, compare=False)
    error: str | None = None

    @property
    def is_stored(self) -> bool:
        """Return whether the value is physically stored in the record."""
        return self.source is ValueSource.STORED

    @property
    def is_empty(self) -> bool:
        """Return whether the value is stored in the record as zero-length data."""
        return self.source is ValueSource.EMPTY

    @property
    def is_null(self) -> bool:
        """Return whether the value is explicitly stored as NULL in the record."""
        return self.source is ValueSource.NULL

    @property
    def is_default(self) -> bool:
        """Return whether the value comes from the column default."""
        return self.source is ValueSource.DEFAULT

    @property
    def is_missing(self) -> bool:
        """Return whether the value is not stored in the record and has no default."""
        return self.source is ValueSource.MISSING

    @property
    def is_corrupt(self) -> bool:
        """Return whether the value is stored in the record but could not be parsed."""
        return self.source is ValueSource.CORRUPT


class _FieldData(NamedTuple):
    """Internal intermediate representation of a record field value and its provenance."""

    source: ValueSource
    value: bytes | None
    offset: int | None
    size: int | None
    tag_field: TagField | None = None


class Record:
    """Wrapper class for records in a table.

    The actual parsing of the data is done in :class:`RecordData`, but this class allows you to easily
    retrieve all the values by either using the `.get()` method, accessing them as attributes or dictionary keys
    on this class.

    Args:
        table: The table this record is from.
        node: The node of this record.
    """

    def __init__(self, table: Table, node: Node):
        self._table = table
        self._esedb = table.esedb
        self._node = node
        self._data = RecordData(table, node)

    def __str__(self) -> str:
        column_values = serialise_record_column_values(self, max_columns=None)
        return f"<Record {column_values}>"

    def __repr__(self) -> str:
        column_values = serialise_record_column_values(self)
        return f"<Record {column_values}>"

    def __hash__(self) -> int:
        return hash((self._table, self._node))

    def __getitem__(self, attr: str) -> RecordValue:
        return self.get(attr)

    def __getattr__(self, attr: str) -> RecordValue:
        try:
            return self.get(attr)
        except KeyError:
            return object.__getattribute__(self, attr)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Record):
            return False

        return self._node.key == value._node.key

    def __ne__(self, value: object) -> bool:
        if not isinstance(value, Record):
            return False

        return self._node.key != value._node.key

    def __lt__(self, value: object) -> bool:
        if not isinstance(value, Record):
            return False

        return self._node.key < value._node.key

    def __le__(self, value: object) -> bool:
        if not isinstance(value, Record):
            return False

        return self._node.key <= value._node.key

    def __gt__(self, value: object) -> bool:
        if not isinstance(value, Record):
            return False

        return self._node.key > value._node.key

    def __ge__(self, value: object) -> bool:
        if not isinstance(value, Record):
            return False

        return self._node.key >= value._node.key

    def get(self, attr: str, raw: bool = False) -> RecordValue:
        """Retrieve a value from the record with the given name.

        Optionally receive the raw data as it's stored in the record.

        Args:
            attr: The column name to retrieve the value of.
            raw: Whether to return the raw data stored in the record instead of the parsed value.
        """
        column = self._table.column(attr)
        return self._data.get(column, raw)

    def field_info(self, attr: str, errors: str | None = "backslashreplace") -> FieldInfo:
        """Retrieve provenance information for the value of the column with the given name.

        Args:
            attr: The column name to retrieve the value provenance of.
            errors: Error handling scheme to use when decoding bytes to text (default: 'backslashreplace').
        """
        column = self._table.column(attr)
        return self._data.field_info(column, errors)

    def as_dict(self, raw: bool = False) -> dict[str, RecordValue]:
        return self._data.as_dict(raw)


class RecordData:
    """Record class for parsing and interacting with the on-disk record format.

    Templated columns are currently not implemented.

    Args:
        table: The table this record is from.
        data: The node data of this record.

    Raises:
        NotImplementedError: If old format tagged fields are encountered.
    """

    def __init__(self, table: Table, node: Node):
        self.table = table
        self.esedb = table.esedb
        self.node = node
        self.data = node.data

        self.header = None
        self._values = {}

        self._last_fixed_id = None
        self._last_variable_id = None

        self._fixed_null_bitmap = None

        self._variable_offset_start = None
        self._variable_data_start = None
        self._variable_offsets = []

        self._tagged_data_start = None
        self._tagged_data_count = 0
        self._tagged_data_view = None
        self._tagged_fields = {}

        if len(self.data) >= 4:
            self.header = c_esedb.RECHDR(self.data)
            self._last_fixed_id = self.header.fidFixedLastInRec
            self._last_variable_id = self.header.fidVarLastInRec
            self._variable_offset_start = self.header.ibEndOfFixedData

            # There's a bitmap between the end of the fixed data and the start of variable data that indicates
            # if a fixed column is null.
            bitmap_start = self._variable_offset_start - ((self._last_fixed_id + 7) // 8)
            self._fixed_null_bitmap = self.data[bitmap_start : self._variable_offset_start]

            # Calculate where the variable offsets array and data start
            # This info is needed for parsing both variable and tagged data
            # Variable identifiers start from 128
            num_variable = self._last_variable_id - 127
            # Variable offset end == variable data start
            self._variable_data_start = self._variable_offset_start + (num_variable * 2)

            if num_variable > 0 and len(self.data) >= 4 + (num_variable * 2):
                # Parse the variable offsets already, if we have them
                # There can only be 128 at most, so this shouldn't be an expensive operation
                self._variable_offsets = struct.unpack(
                    f"<{num_variable}H", self.data[self._variable_offset_start : self._variable_data_start]
                )

            self._tagged_data_start = self._variable_data_start
            if self._variable_offsets:
                self._tagged_data_start += self._variable_offsets[-1] & 0x7FFF

            if len(self.data) >= self._tagged_data_start + 4:
                if node.tag.page.flags & PAGE_FLAG.NewRecordFormat == 0:
                    raise NotImplementedError("Record has tagged fields in an old format, which is not implemented yet")

                tag_value = int.from_bytes(self.data[self._tagged_data_start : self._tagged_data_start + 4], "little")
                first_tagged_field = TagField(self, tag_value)

                tagged_field_data_start = self._tagged_data_start
                tagged_field_data_end = tagged_field_data_start + first_tagged_field.offset
                tagged_field_data = self.data[self._tagged_data_start : tagged_field_data_end]

                self._tagged_data_count = first_tagged_field.offset // 4  # sizeof(TAGFLD)
                self._tagged_data_view = xmemoryview(tagged_field_data, "<I")
                self._tagged_fields[first_tagged_field.identifier] = first_tagged_field

        self._get_tag_field = lru_cache(4096)(self._get_tag_field)
        self._find_tag_field_idx = lru_cache(4096)(self._find_tag_field_idx)

    def get(self, column: Column, raw: bool = False, errors: str | None = "backslashreplace") -> RecordValue:
        """Retrieve the value for the specified column.

        Optionally receive the raw data as it's stored in the record.

        If the database has been opened in impacket compatibility mode, skip most of the parsing and return the values
        that impacket expects.

        Args:
            column: The column to retrieve the value of.
            raw: Whether to return the raw data stored in the record instead of the parsed value.
            errors: Error handling scheme to use when decoding bytes to text (default: 'backslashreplace').
        """
        field = self._get_field(column)
        value = field.value

        if raw:
            if isinstance(value, memoryview):
                value = value.tobytes()
            return value

        if value is not None:
            return self._parse_value(column, value, field.tag_field, errors)

        return None

    def field_info(self, column: Column, errors: str | None = "backslashreplace") -> FieldInfo:
        """Retrieve provenance information for the value of the specified column.

        Both the raw and the parsed interpretation are derived from the same source determination, so they are
        always consistent with each other. Values that fail to parse are reported with a
        :attr:`ValueSource.CORRUPT` source instead of raising an exception.

        Args:
            column: The column to retrieve the value provenance of.
            errors: Error handling scheme to use when decoding bytes to text (default: 'backslashreplace').
        """
        field = self._get_field(column)
        source = field.source

        raw = field.value
        if isinstance(raw, memoryview):
            raw = raw.tobytes()

        value = None
        error = None
        if raw is not None:
            try:
                value = self._parse_value(column, raw, field.tag_field, errors)
            except Exception as e:
                source = ValueSource.CORRUPT
                error = f"{type(e).__name__}: {e}"

        return FieldInfo(
            column=column,
            source=source,
            value=value,
            raw=raw,
            offset=field.offset,
            size=field.size,
            tag_field=field.tag_field,
            error=error,
        )

    def _get_field(self, column: Column) -> _FieldData:
        """Retrieve the raw value and provenance of the specified column from the record."""
        if self.header is None:
            return _FieldData(ValueSource.MISSING, None, None, None)

        if column.is_fixed:
            return self._get_fixed(column)

        if column.is_variable:
            return self._get_variable(column)

        return self._get_tagged(column)

    def _get_default(self, column: Column) -> _FieldData:
        """Return the provenance for a column that is not stored in the record."""
        if column.default is not None:
            return _FieldData(ValueSource.DEFAULT, column.default, None, None)
        return _FieldData(ValueSource.MISSING, None, None, None)

    def as_dict(self, raw: bool = False, errors: str | None = "backslashreplace") -> dict[str, RecordValue]:
        """Serialize the record as a dictionary."""
        obj = {}

        def _iter_column_id() -> Iterator[Column]:
            # Fixed
            yield from range(1, self._last_fixed_id + 1)

            # Variable
            yield from range(128, self._last_variable_id + 1)

            # Tagged
            for idx in range(self._tagged_data_count):
                yield self._get_tag_field(idx).identifier

        for column_id in _iter_column_id():
            column = self.table._column_id_map[column_id]

            try:
                obj[column.name] = self.get(column, raw, errors)
            except Exception as e:
                obj[column.name] = f"!ERROR! {e}"

        return obj

    def _parse_value(
        self, column: Column, value: bytes, tag_field: TagField = None, errors: str | None = "backslashreplace"
    ) -> RecordValue:
        """Parse the raw value into the appropriate type.

        For tagged columns, also interpret things like multi-values, separated and compressed data.
        """
        ctype = column.ctype
        parse_func = ctype.parse
        if column.is_text:
            parse_func = functools.partial(ctype.parse, encoding=column.encoding, errors=errors)

        if self.esedb.impacket_compat:
            if tag_field and tag_field.flags & TAGFLD_HEADER.Compressed:
                value = None
            elif tag_field and tag_field.flags & TAGFLD_HEADER.MultiValues:
                value = hexlify(value)
            elif parse_func is not bytes:
                value = parse_func(value)
            else:
                value = hexlify(value)
        else:
            if tag_field:
                if tag_field.flags & TAGFLD_HEADER.MultiValues:
                    value = self._parse_multivalue(value, tag_field)
                else:
                    if tag_field.flags & TAGFLD_HEADER.Separated:
                        value = self.table.get_long_value(bytes(value))
                    elif tag_field.flags & TAGFLD_HEADER.Compressed:
                        # Long values are already decompressed during retrieval
                        value = compression.decompress(value)

            parse_func = parse_func or noop
            if tag_field and tag_field.flags & TAGFLD_HEADER.MultiValues:
                value = list(map(parse_func, value))
            else:
                value = parse_func(value)

        return value

    def _parse_multivalue(self, value: bytes, tag_field: TagField) -> list[bytes]:
        fSeparatedInstance = 0x8000

        if len(value) == 0:
            # An empty multi-value list is stored as zero-length data
            return []

        if tag_field.flags & TAGFLD_HEADER.TwoValues:
            # Optimized storage for when a multi-value only has two values
            # First byte is the size of the first value, calculate the size of the second value from that
            first_size = value[0]
            second_size = len(value) - (1 + first_size)
            value = [value[1 : 1 + first_size], value[1 + first_size : 1 + first_size + second_size]]
        elif tag_field.flags & TAGFLD_HEADER.MultiValues:
            # Regular multi-value storage, starts with an array of USHORT offsets to the actual values
            # Just calculate the amount of values from the first entry
            # Individual offsets can have a fSeparatedInstance (0x8000) flag set
            first_value_offset = struct.unpack("<H", value[0:2])[0] & 0x7FFF
            num_values = first_value_offset // 2  # sizeof(USHORT)
            value_offsets = (*struct.unpack(f"<{num_values}H", value[:first_value_offset]), len(value))

            values = []
            for i in range(num_values):
                offset = value_offsets[i]
                data = value[offset & 0x7FFF : value_offsets[i + 1] & 0x7FFF]
                if offset & fSeparatedInstance:
                    data = self.table.get_long_value(bytes(data))
                values.append(data)
            value = values
        else:
            raise ValueError(f"Unknown flags for tag field: {tag_field}")

        if tag_field.flags & TAGFLD_HEADER.Compressed:
            # Only the first entry appears to be compressed
            value[0] = compression.decompress(value[0])

        return value

    def _get_fixed(self, column: Column) -> _FieldData:
        """Parse a specific fixed column."""
        if column.identifier <= self._last_fixed_id:
            # Fixed data starts right after the header, which is 4 bytes
            offset = 4 + column.offset
            size = column.size

            # Check if it's not null
            bit_idx_identifier = column.identifier - 1
            bitmap_offset, bitmap_shift = divmod(bit_idx_identifier, 8)
            if self._fixed_null_bitmap[bitmap_offset] & (1 << bitmap_shift):
                return _FieldData(ValueSource.NULL, None, offset, size)

            value = self.data[offset : offset + size]
            source = ValueSource.EMPTY if len(value) == 0 else ValueSource.STORED
            return _FieldData(source, value, offset, size)

        # If the column has a default, use that
        # If not, this defaults to None
        return self._get_default(column)

    def _get_variable(self, column: Column) -> _FieldData:
        """Parse a specific variable column."""
        if column.identifier <= self._last_variable_id:
            identifier_idx = column.identifier - 128

            # Start of this value is the end of the previous value
            # Even empty values have the offset encoded in them
            value_start = 0 if identifier_idx == 0 else self._variable_offsets[identifier_idx - 1] & 32767

            # The value at the own index is the end offset of this value
            value_end = self._variable_offsets[identifier_idx]

            # Offset everything with the variable data value starting offset
            offset = self._variable_data_start + value_start
            size = (value_end & 0x7FFF) - value_start

            # If the MSB has been set, it means the entry is empty
            if value_end & 0x8000:
                return _FieldData(ValueSource.NULL, None, offset, size)

            value = self.data[offset : offset + size]
            source = ValueSource.EMPTY if size == 0 else ValueSource.STORED
            return _FieldData(source, value, offset, size)

        # If the column has a default, use that
        # If not, this defaults to None
        return self._get_default(column)

    def _get_tagged(self, column: Column) -> _FieldData:
        """Parse a specific tagged column."""
        idx = self._find_tag_field_idx(column.identifier)
        if idx is None:
            # If the column has a default, use that
            # If not, this defaults to None
            return self._get_default(column)

        tag_field = self._get_tag_field(idx)

        data_start = tag_field.offset
        if tag_field.has_extended_info:
            data_start += 1

        data_end = (
            self._get_tag_field(idx + 1).offset
            if idx + 1 < self._tagged_data_count
            else len(self.data) - self._tagged_data_start
        )

        offset = self._tagged_data_start + data_start
        size = data_end - data_start

        if tag_field.is_null:
            return _FieldData(ValueSource.NULL, None, offset, size, tag_field)

        value = self.data[offset : offset + size]
        source = ValueSource.EMPTY if size == 0 else ValueSource.STORED
        return _FieldData(source, value, offset, size, tag_field)

    def _get_tag_field(self, idx: int) -> TagField:
        """Retrieve the :class:`TagField` at the given index in the ``TAGFLD`` array."""
        return TagField(self, self._tagged_data_view[idx])

    def _find_tag_field_idx(self, identifier: int, is_derived: bool = False) -> TagField | None:
        """Find a tag field by identifier and optional derived flag.

        Performs a binary search in the tagged field array for the given identifier. The comparison algorithm used is
        derived from the ``TAGFLD::CmpTagfld2`` function in the Microsoft codebase.

        Args:
            identifier: The column identifier to look for.
            is_derived: A flag indicating if the column is derived.

        Returns:
            A :class:`TagField` object for the found tag field, or ``None`` if it's not found.
        """
        if self._tagged_data_count == 0:
            return None

        lookup = identifier
        if is_derived:
            lookup |= TagField.fDerived << 16  # fDerived

        # TAGFLD::CmpTagfld2
        flip_derived = TagField.fDerived << 16
        mask = flip_derived | ((1 << 16) - 1)
        value2 = flip_derived ^ (lookup & mask)

        min_idx = 0
        max_idx = self._tagged_data_count - 1

        while min_idx != max_idx:
            test_idx = min_idx + (max_idx - min_idx) // 2

            tag_value = self._tagged_data_view[test_idx]
            value1 = flip_derived ^ (tag_value & mask)
            if value1 < value2:
                min_idx = test_idx + 1
            elif value1 == value2:
                min_idx = test_idx
                break
            else:
                max_idx = test_idx

        tag_value = self._tagged_data_view[min_idx]
        if tag_value & 0xFFFF == identifier:
            return min_idx

        return None


class TagField:
    """Represents a ``TAGFLD``, which contains information about a tagged field in a record."""

    __slots__ = ("_offset", "flags", "has_extended_info", "identifier", "offset", "record")

    fNullSmallPage = 0x2000
    fDerived = 0x8000

    def __init__(self, record: RecordData, value: int):
        self.record = record
        self.identifier = value & 0xFFFF
        self._offset = (value >> 16) & 0xFFFF

        if record.esedb.has_small_pages:
            self.offset = self._offset & 0x1FFF  # & maskIb
            self.has_extended_info = bool(self._offset & 0x4000)  # & fExtendedInfo
        else:
            self.offset = self._offset & 0x7FFF  # & maskIb
            self.has_extended_info = True

        if self.has_extended_info and len(self.record.data) >= self.record._tagged_data_start + self.offset:
            self.flags = TAGFLD_HEADER(self.record.data[self.record._tagged_data_start + self.offset])
        else:
            self.flags = TAGFLD_HEADER.Invalid  # Made up flag member to keep the types consistent

    def __repr__(self) -> str:
        return f"<TagField identifier={self.identifier} offset={self.offset:#x} flags={str(self.flags).split('.')[1]}>"

    @property
    def is_null(self) -> bool:
        """Return whether this tagged field is null."""
        if self.record.esedb.has_small_pages:
            return bool(self._offset & TagField.fNullSmallPage)
        return bool(self.flags & TAGFLD_HEADER.Null)

    @property
    def is_derived(self) -> bool:
        """Return whether this tagged field is derived."""
        return bool(self._offset & TagField.fDerived)


def serialise_record_column_values(record: Record, column_names: list[str] | None = None, max_columns: int = 10) -> str:
    column_names = column_names or record._table.column_names
    columns_with_values = []
    for name in column_names:
        try:
            value = record.get(name)
        except Exception:
            value = "!ERROR!"

        if value is not None:
            columns_with_values.append((name, value))

        if max_columns and len(columns_with_values) >= max_columns:
            break

    reprs = " ".join([f"{name}={value!r}" for (name, value) in columns_with_values])
    has_more = " ..." if max_columns and len(column_names) > max_columns else ""
    return f"{reprs}{has_more}"
