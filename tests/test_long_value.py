from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING, BinaryIO

import pytest
from dissect.util.compression import sevenbit

from dissect.esedb.c_esedb import PAGE_FLAG, TAG_FLAG, c_esedb
from dissect.esedb.esedb import EseDB
from dissect.esedb.exceptions import LongValueError
from dissect.esedb.page import Page
from dissect.esedb.table import Table
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterable

PAGE_SIZE = 4096
LV_PAGE_FLAGS = PAGE_FLAG.Leaf | PAGE_FLAG.LongValue | PAGE_FLAG.NewRecordFormat | PAGE_FLAG.NewChecksumFormat
LV_ROOT_FLAGS = (
    PAGE_FLAG.Root
    | PAGE_FLAG.ParentOfLeaf
    | PAGE_FLAG.LongValue
    | PAGE_FLAG.NewRecordFormat
    | PAGE_FLAG.NewChecksumFormat
)


class FakeEseDB:
    """Minimal EseDB stand-in that serves synthetic long value pages."""

    has_small_pages = True

    def __init__(self) -> None:
        self.pages: dict[int, Page] = {}

    def page(self, num: int) -> Page:
        return self.pages[num]


class FakeLongValueRecord:
    """Stand-in for the catalog record that points at the long value page."""

    def __init__(self, page: int) -> None:
        self.page = page

    def get(self, name: str) -> int:
        assert name == "ColtypOrPgnoFDP"
        return self.page


def build_page(
    flags: PAGE_FLAG,
    nodes: Iterable[tuple[bytes, bytes]],
    *,
    next_page: int = 0,
    previous_page: int = 0,
    compressed_tags: set[int] | None = None,
) -> bytes:
    """Build a single physical ESE page containing leaf nodes.

    Args:
        flags: Page flags to set.
        nodes: Pairs of ``(key, data)`` that become tags ``1..n``.
        next_page: Logical page number of the next page.
        previous_page: Logical page number of the previous page.
        compressed_tags: Indices into ``nodes`` whose tag should have the compressed flag set.
    """
    compressed_tags = compressed_tags or set()

    # Tag 0 is reserved by the format for the page key prefix.
    entries = [(0, 1, TAG_FLAG(0), b"\x00")]
    cursor = 1

    for i, (key, data) in enumerate(nodes):
        raw = struct.pack("<H", len(key)) + key + data
        tag_flags = TAG_FLAG.Compressed if i in compressed_tags else TAG_FLAG(0)
        entries.append((cursor, len(raw), tag_flags, raw))
        cursor += len(raw)

    data_area = b"".join(entry[3] for entry in entries)
    buf = bytearray(PAGE_SIZE)

    header = c_esedb.PGHDR(
        fFlags=flags,
        pgnoPrev=previous_page,
        pgnoNext=next_page,
        ibMicFree=len(data_area),
        itagState=len(entries),
    ).dumps()
    buf[: len(header)] = header
    buf[len(header) : len(header) + len(data_area)] = data_area

    for i, (offset, size, tag_flags, _) in enumerate(entries):
        ib = offset | (int(tag_flags) << 13)
        struct.pack_into("<HH", buf, PAGE_SIZE - 4 * (i + 1), size, ib)

    return bytes(buf)


def make_table(leaf_pages: list[tuple[int, list[tuple[bytes, bytes]], set[int]]]) -> Table:
    """Create a table whose long value tree consists of the given leaf pages.

    Args:
        leaf_pages: Ordered ``(page_number, nodes, compressed_tag_indices)`` tuples.
    """
    db = FakeEseDB()
    page_numbers = [page[0] for page in leaf_pages]

    for i, (page_number, nodes, compressed_tags) in enumerate(leaf_pages):
        buf = build_page(
            LV_PAGE_FLAGS,
            nodes,
            next_page=page_numbers[i + 1] if i + 1 < len(page_numbers) else 0,
            previous_page=page_numbers[i - 1] if i > 0 else 0,
            compressed_tags=compressed_tags,
        )
        db.pages[page_number] = Page(db, page_number, buf)

    # A root page with a branch node pointing at the first leaf.
    root = build_page(LV_ROOT_FLAGS, [(b"\x00\x00\x00\x01", struct.pack("<I", page_numbers[0]))])
    db.pages[32] = Page(db, 32, root)

    table = Table(db, "long_value", 32)
    table._long_value_record = FakeLongValueRecord(32)
    return table


def lv_key(identifier: int, size: int | None = None) -> tuple[bytes, bytes]:
    """Build the (reversed) header key and data for a long value."""
    key = struct.pack("<I", identifier)[::-1]
    if size is None:
        return key, b""
    return key, struct.pack("<2I", identifier, size)


def chunk_key(identifier: int, offset: int) -> bytes:
    """Build a chunk key for the given value identifier and logical offset."""
    return struct.pack("<I", identifier)[::-1] + struct.pack(">I", offset)


def test_get_long_value_multi_chunk_across_pages() -> None:
    """A value spanning multiple pages should assemble in order and expose chunk evidence."""
    a, b, c = b"A" * 10, b"B" * 10, b"C" * 10

    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 30),
                    (chunk_key(1, 0), a),
                ],
                set(),
            ),
            (
                44,
                [
                    (chunk_key(1, 10), b),
                    (chunk_key(1, 20), c),
                ],
                set(),
            ),
        ]
    )

    data, chunks = table.get_long_value_chunks(bytes([1, 0, 0, 0]))

    assert data == a + b + c
    assert [chunk.offset for chunk in chunks] == [0, 10, 20]
    assert [chunk.length for chunk in chunks] == [10, 10, 10]
    assert [chunk.page for chunk in chunks] == [43, 44, 44]
    assert [chunk.tag for chunk in chunks] == [2, 1, 2]
    assert all(chunk.tag_flags == TAG_FLAG(0) for chunk in chunks)
    assert all(chunk.compression == 0 for chunk in chunks)
    assert all(chunk.decompressed_size == 10 for chunk in chunks)
    assert b"".join(chunk.value for chunk in chunks) == data


def test_get_long_value_does_not_mix_in_next_value() -> None:
    """Chunks of a following long value must never be appended to the current one."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 20),
                    (chunk_key(1, 0), b"A" * 10),
                    (chunk_key(1, 10), b"B" * 10),
                    lv_key(2, 10),
                    (chunk_key(2, 0), b"C" * 10),
                ],
                set(),
            )
        ]
    )

    assert table.get_long_value(bytes([1, 0, 0, 0])) == b"A" * 10 + b"B" * 10
    assert table.get_long_value(bytes([2, 0, 0, 0])) == b"C" * 10


def test_get_long_value_missing_chunk() -> None:
    """A gap left by a missing chunk must fail with evidence pointing at the last intact chunk."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 30),
                    (chunk_key(1, 0), b"A" * 10),
                    (chunk_key(1, 20), b"C" * 10),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError) as exc_info:
        table.get_long_value(bytes([1, 0, 0, 0]))

    error = exc_info.value
    assert error.key == b"\x01\x00\x00\x00"
    assert error.declared_size == 30
    assert error.chunk.offset == 0
    assert error.chunk.page == 43
    assert error.chunk.tag == 2
    assert [chunk.offset for chunk in error.evidence] == [0]


def test_get_long_value_wrong_first_offset() -> None:
    """A value that starts at a non-zero offset is missing its first chunk."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 30),
                    (chunk_key(1, 10), b"B" * 10),
                    (chunk_key(1, 20), b"C" * 10),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError, match="missing its first chunk") as exc_info:
        table.get_long_value(bytes([1, 0, 0, 0]))

    assert exc_info.value.chunk.offset == 10
    assert exc_info.value.chunk.page == 43
    assert exc_info.value.chunk.tag == 2


def test_get_long_value_duplicate_offset() -> None:
    """A repeated chunk offset must be rejected."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 20),
                    (chunk_key(1, 0), b"A" * 10),
                    (chunk_key(1, 10), b"B" * 10),
                    (chunk_key(1, 10), b"C" * 10),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError, match="Duplicate or out of order") as exc_info:
        table.get_long_value(bytes([1, 0, 0, 0]))

    assert exc_info.value.chunk.offset == 10
    assert exc_info.value.chunk.tag == 4


def test_get_long_value_offset_beyond_declared_size() -> None:
    """A chunk that starts at or beyond the declared size is invalid."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 10),
                    (chunk_key(1, 0), b"A" * 10),
                    (chunk_key(1, 20), b"C" * 10),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError, match="exceeds declared size") as exc_info:
        table.get_long_value(bytes([1, 0, 0, 0]))

    assert exc_info.value.chunk.offset == 20
    assert exc_info.value.chunk.page == 43
    assert exc_info.value.chunk.tag == 3


def test_get_long_value_declared_size_mismatch() -> None:
    """A trailing gap relative to the declared size must fail."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 30),
                    (chunk_key(1, 0), b"A" * 10),
                    (chunk_key(1, 10), b"B" * 10),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError) as exc_info:
        table.get_long_value(bytes([1, 0, 0, 0]))

    assert exc_info.value.declared_size == 30
    assert [chunk.offset for chunk in exc_info.value.evidence] == [0, 10]


def test_get_long_value_compressed_chunk() -> None:
    """A chunk whose compressed size differs from the expected size should decompress."""
    payload = b"abcdefghijklmnop"
    compressed = bytes([0x08]) + sevenbit.compress(payload)

    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, len(payload)),
                    (chunk_key(1, 0), compressed),
                ],
                set(),
            )
        ]
    )

    data, chunks = table.get_long_value_chunks(bytes([1, 0, 0, 0]))

    assert data == payload
    assert chunks[0].value == payload
    assert chunks[0].data == compressed
    assert chunks[0].length == len(compressed)
    assert chunks[0].decompressed_size == len(payload)
    assert chunks[0].compression == 1


def test_get_long_value_not_compressed_despite_length_mismatch() -> None:
    """A length mismatch alone must not be treated as compression."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 20),
                    (chunk_key(1, 0), b"\x00" + b"X" * 9),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError, match="but is not compressed"):
        table.get_long_value(bytes([1, 0, 0, 0]))


def test_get_long_value_compressed_wrong_decompressed_size() -> None:
    """A compressed chunk that does not expand to the expected size must fail."""
    compressed = bytes([0x08]) + sevenbit.compress(b"abc")

    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 9),
                    (chunk_key(1, 0), compressed),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError, match="expected 9"):
        table.get_long_value(bytes([1, 0, 0, 0]))


def test_get_long_value_empty() -> None:
    """A value that declares zero bytes has no chunks."""
    table = make_table([(43, [lv_key(1, 0)], set())])

    assert table.get_long_value(bytes([1, 0, 0, 0])) == b""


def test_get_long_value_real_multichunk(windows_search_db: BinaryIO) -> None:
    """The bundled Windows database contains a value spanning seven chunks on two pages."""
    fixture = absolute_path("_data/Windows.edb.gz")
    digest_before = hashlib.sha256(fixture.read_bytes()).hexdigest()

    db = EseDB(windows_search_db)
    table = db.table("SystemIndex_1_Properties")

    key = bytes.fromhex("0100008000000080")
    data, chunks = table.get_long_value_chunks(key)

    assert len(data) == 56448
    assert len(chunks) == 7
    assert [chunk.offset for chunk in chunks] == [0, 8150, 16300, 24450, 32600, 40750, 48900]
    assert [chunk.page for chunk in chunks] == [55, 55, 55, 55, 56, 56, 56]
    assert [chunk.tag for chunk in chunks] == [2, 3, 4, 5, 1, 2, 3]
    assert [chunk.length for chunk in chunks] == [8150, 8150, 8150, 8150, 8150, 8150, 7548]
    assert all(chunk.decompressed_size == chunk.length for chunk in chunks)
    # The raw tag flags, including the compressed marker written by ESE, must be preserved as evidence.
    assert all(chunk.tag_flags & TAG_FLAG.Version for chunk in chunks)

    # Reading the value must leave the source database untouched.
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == digest_before


def test_get_long_value_short_header() -> None:
    """A header without room for an identifier and size must fail cleanly."""
    short_header = struct.pack("<I", 1)[::-1]
    table = make_table([(43, [(short_header, b"\x01\x00\x00"), (chunk_key(1, 0), b"A" * 10)], set())])

    with pytest.raises(LongValueError, match="header is too small"):
        table.get_long_value(bytes([1, 0, 0, 0]))


def test_get_long_value_missing_all_chunks() -> None:
    """A non-empty declared value without any chunks must fail cleanly."""
    table = make_table([(43, [lv_key(1, 30)], set())])

    with pytest.raises(LongValueError, match="no chunks"):
        table.get_long_value(bytes([1, 0, 0, 0]))


def test_get_long_value_duplicate_header() -> None:
    """Encountering the header again while collecting chunks must fail."""
    header = lv_key(1, 30)
    table = make_table(
        [
            (
                43,
                [
                    header,
                    (chunk_key(1, 0), b"A" * 10),
                    header,
                    (chunk_key(1, 20), b"C" * 10),
                ],
                set(),
            )
        ]
    )

    with pytest.raises(LongValueError, match="Duplicate long value header"):
        table.get_long_value(bytes([1, 0, 0, 0]))


def test_get_long_value_repeated_reads_are_stable() -> None:
    """Chunk evidence must be stable across repeated reads and the source must stay read-only."""
    table = make_table(
        [
            (
                43,
                [
                    lv_key(1, 20),
                    (chunk_key(1, 0), b"A" * 10),
                    (chunk_key(1, 10), b"B" * 10),
                ],
                set(),
            )
        ]
    )
    page_buf_before = bytes(table.lv_page.buf)

    first, first_chunks = table.get_long_value_chunks(bytes([1, 0, 0, 0]))
    second = table.get_long_value(bytes([1, 0, 0, 0]))

    assert first == second == b"A" * 10 + b"B" * 10
    assert [chunk.page for chunk in first_chunks] == [43, 43]
    assert bytes(table.lv_page.buf) == page_buf_before
