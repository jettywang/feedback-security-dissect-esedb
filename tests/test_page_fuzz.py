from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from typing import BinaryIO

import pytest

from dissect.esedb.btree import BTree
from dissect.esedb.c_esedb import PAGE_FLAG, TAG_FLAG, c_esedb
from dissect.esedb.esedb import EseDB
from dissect.esedb.exceptions import InvalidPage, NoNeighbourPageError
from dissect.esedb.page import Page

SMALL_PAGE = 4096
LARGE_PAGE = 16384
SMALL_MASK = 0x1FFF
LARGE_MASK = 0x7FFF

# Fixed seeds make failures reproducible.
FUZZ_SEEDS = (0x5EED0001, 0x5EED0002, 0xC0FFEE01)
FUZZ_ITERATIONS = 120


class FakeDB:
    """The minimum of EseDB needed by Page and BTree."""

    def __init__(self, page_size: int):
        self.page_size = page_size

    @property
    def has_small_pages(self) -> bool:
        return self.page_size <= 8192


def is_small(page_size: int) -> bool:
    return page_size <= 8192


def data_start(page_size: int) -> int:
    return len(c_esedb.PGHDR) + (0 if is_small(page_size) else len(c_esedb.PGHDR2))


def tag_position(page_size: int, num: int) -> int:
    return page_size - (num + 1) * len(c_esedb.TAG)


def tag_mask(page_size: int) -> int:
    return SMALL_MASK if is_small(page_size) else LARGE_MASK


@dataclass
class NodeSpec:
    """A node described by what we intend to write, not by parsing it back."""

    key_suffix: bytes = b""
    data: bytes = b""
    prefix_ref: int | None = None
    flags: int = 0


@dataclass
class PageSpec:
    page_size: int = SMALL_PAGE
    flags: int = PAGE_FLAG.Leaf
    prefix: bytes = b""
    nodes: list[NodeSpec] = field(default_factory=list)
    prev: int = 0
    next: int = 0
    tag_reserved: int = 1


def encode_node(node: NodeSpec, small: bool) -> bytes:
    """Encode a node body.

    Small pages keep node flags in the tag offset word. Large pages keep them in the 3 MSBs of the first
    USHORT of the node body, which is either the prefix reference word or the suffix length word.
    """
    buf = bytearray()
    # A prefix reference is only meaningful when the node is marked as compressed.
    flags = node.flags | (TAG_FLAG.Compressed if node.prefix_ref is not None else 0)
    flag_bits = (flags & 0x7) << 13

    if node.prefix_ref is not None:
        buf += struct.pack("<H", (node.prefix_ref & SMALL_MASK) | (0 if small else flag_bits))

    suffix_len = len(node.key_suffix)
    if node.prefix_ref is None and not small:
        buf += struct.pack("<H", (suffix_len & SMALL_MASK) | flag_bits)
    else:
        buf += struct.pack("<H", suffix_len & SMALL_MASK)

    return bytes(buf) + node.key_suffix + node.data


def encode_page(spec: PageSpec) -> tuple[bytes, list[tuple[int, int]]]:
    """Encode an explicit page layout.

    Returns the page bytes and the ``(offset, size)`` of each node body, relative to the page data area.
    """
    small = is_small(spec.page_size)
    bodies = [encode_node(node, small) for node in spec.nodes]
    tag_count = len(bodies) + 1

    positions = []
    cur = len(spec.prefix)
    for body in bodies:
        positions.append((cur, len(body)))
        cur += len(body)
    ib_mic_free = cur

    assert spec.page_size - tag_count * 4 >= data_start(spec.page_size) + ib_mic_free, "layout does not fit page"

    raw = bytearray(b"\x00" * spec.page_size)
    raw[: len(c_esedb.PGHDR)] = c_esedb.PGHDR(
        pgnoPrev=spec.prev,
        pgnoNext=spec.next,
        ibMicFree=ib_mic_free,
        itagState=(spec.tag_reserved << 12) | (tag_count & 0xFFF),
        fFlags=PAGE_FLAG(spec.flags),
    ).dumps()
    if not small:
        header2 = c_esedb.PGHDR2().dumps()
        raw[len(c_esedb.PGHDR) : len(c_esedb.PGHDR) + len(header2)] = header2

    start = data_start(spec.page_size)
    raw[start : start + len(spec.prefix)] = spec.prefix
    for body, (offset, _) in zip(bodies, positions, strict=True):
        raw[start + offset : start + offset + len(body)] = body

    offsets = []
    cur = 0
    for size in [len(spec.prefix), *(len(body) for body in bodies)]:
        offsets.append(cur)
        cur += size

    mask = tag_mask(spec.page_size)
    for num in range(tag_count):
        if num == 0:
            size, offset, flags = len(spec.prefix), 0, 0
        else:
            offset, size = positions[num - 1]
            node = spec.nodes[num - 1]
            flags = node.flags | (TAG_FLAG.Compressed if node.prefix_ref is not None else 0)
        tag_ib = (offset & mask) | (((flags & 0x7) << 13) if small else 0)
        struct.pack_into("<HH", raw, tag_position(spec.page_size, num), size & mask, tag_ib)

    return bytearray(raw), positions


class OracleInvalid(Exception):
    """The hand-written oracle concluded this page cannot describe every node exactly."""


@dataclass
class OracleNode:
    offset: int
    size: int
    flags: int
    key_prefix: bytes
    key_suffix: bytes
    key: bytes
    data: bytes
    child: int | None = None


@dataclass
class OraclePage:
    data_size: int
    tag_count: int
    node_count: int
    nodes: list[OracleNode]


def read_u16(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<H", raw, offset)[0]


def oracle_page(raw: bytes, page_size: int) -> OraclePage:
    """Independently decode a page with explicit struct offsets and hard length comparisons.

    This deliberately does not use Page, Tag or Node. Every offset and size below is computed from the
    documented ESE layout, so it is a second opinion rather than a mirror of the parser.
    """
    if len(raw) != page_size or page_size < data_start(page_size):
        raise OracleInvalid("page has an invalid size")

    small = is_small(page_size)
    ib_mic_free = read_u16(raw, 32)  # PGHDR.ibMicFree
    itag_state = read_u16(raw, 34)  # PGHDR.itagState
    page_flags = struct.unpack_from("<I", raw, 36)[0]  # PGHDR.fFlags

    start = data_start(page_size)
    data_end = start + ib_mic_free
    if data_end > page_size:
        raise OracleInvalid("data area extends past page body")

    tag_count = itag_state & 0x0FFF
    reserved = (itag_state >> 12) or 1
    node_count = tag_count - reserved
    if tag_count and page_size - tag_count * 4 < data_end:
        raise OracleInvalid("tag array overlaps data area")

    data = raw[start:data_end]
    mask = tag_mask(page_size)
    leaf = bool(page_flags & PAGE_FLAG.Leaf)
    nodes: list[OracleNode] = []

    def read_tag(num: int) -> tuple[int, int, int]:
        pos = tag_position(page_size, num)
        if pos < 0 or pos + 4 > page_size:
            raise OracleInvalid(f"tag {num} outside page")
        cb, ib = struct.unpack_from("<HH", raw, pos)
        size, offset = cb & mask, ib & mask
        if offset + size > len(data):
            raise OracleInvalid(f"tag {num} extends past data area")
        if size == 0 and num != 0:
            raise OracleInvalid(f"tag {num} has zero size")
        return size, offset, (ib >> 13)

    prefix = b""
    if tag_count:
        size, offset, _ = read_tag(0)
        prefix = data[offset : offset + size]

    for num in range(1, tag_count):
        size, offset, tag_flags = read_tag(num)
        body = data[offset : offset + size]
        if len(body) != size:
            raise OracleInvalid(f"node {num} has a short body")

        flags = tag_flags if small else (body[1] >> 5 if len(body) >= 2 else 0)
        key_prefix = b""
        pos = 0

        if flags & TAG_FLAG.Compressed:
            if len(body) < 2:
                raise OracleInvalid(f"node {num} has no prefix word")
            prefix_ref = read_u16(body, 0) & SMALL_MASK
            if prefix_ref > len(prefix):
                raise OracleInvalid(f"node {num} references past common prefix")
            key_prefix = prefix[:prefix_ref]
            pos = 2

        if len(body) < pos + 2:
            raise OracleInvalid(f"node {num} has no suffix word")
        suffix_len = read_u16(body, pos) & SMALL_MASK
        pos += 2
        if pos + suffix_len > len(body):
            raise OracleInvalid(f"node {num} suffix extends past tag data")
        key_suffix = body[pos : pos + suffix_len]
        pos += suffix_len

        node_data = body[pos:]
        child = None
        if not leaf:
            if len(node_data) < 4:
                raise OracleInvalid(f"node {num} has no branch child")
            child = struct.unpack("<I", node_data[:4])[0]

        nodes.append(
            OracleNode(
                offset=offset,
                size=size,
                flags=int(flags),
                key_prefix=key_prefix,
                key_suffix=key_suffix,
                key=key_prefix + key_suffix,
                data=node_data,
                child=child,
            )
        )

    return OraclePage(data_size=len(data), tag_count=tag_count, node_count=node_count, nodes=nodes)


def parse_page(page_size: int, raw: bytes) -> Page:
    return Page(FakeDB(page_size), 0, raw)


def assert_page_matches_oracle(page: Page, expected: OraclePage) -> None:
    assert len(page.data) == expected.data_size
    assert page.tag_count == expected.tag_count
    assert page.node_count == expected.node_count
    assert len(expected.nodes) == expected.node_count

    for num, node in enumerate(page.nodes()):
        item = expected.nodes[num]
        assert node.tag.num == num + 1
        assert node.tag.offset == item.offset
        assert node.tag.size == item.size
        assert node.tag.flags == item.flags
        assert node.key_prefix == item.key_prefix
        assert node.key_suffix == item.key_suffix
        assert node.key == item.key
        # Compare the exact data range, not just a prefix: Python slicing would hide a short read.
        assert node.data == item.data
        assert len(node.data) == len(item.data)
        if item.child is not None:
            assert node.child == item.child


def basic_spec(page_size: int, *, leaf: bool = True, root: bool = False) -> PageSpec:
    prefix = b"common-pre"
    specs = [
        NodeSpec(prefix_ref=3, key_suffix=b"ant", data=b"value-0"),
        NodeSpec(key_suffix=b"bravo", data=b"value-1"),
        NodeSpec(prefix_ref=len(prefix), key_suffix=b"", data=b"value-2"),
        NodeSpec(prefix_ref=0, key_suffix=b"delta", data=b"value-3"),
    ]
    if not leaf:
        for child, node in enumerate(specs, start=1):
            node.data = struct.pack("<I", child) + node.data

    flags = PAGE_FLAG.Leaf if leaf else 0
    if root:
        flags |= PAGE_FLAG.Root
    return PageSpec(page_size=page_size, flags=flags, prefix=prefix, nodes=specs)


def test_small_page_hand_layout_matches_oracle() -> None:
    spec = basic_spec(SMALL_PAGE)
    raw, positions = encode_page(spec)
    page = parse_page(SMALL_PAGE, raw)
    expected = oracle_page(raw, SMALL_PAGE)

    # Hand-calculated layout: tag 0 owns the common prefix at offset 0, nodes follow contiguously.
    assert page.tag(0).offset == 0
    assert page.tag(0).size == len(spec.prefix)
    cursor = len(spec.prefix)
    for num, (offset, size) in enumerate(positions, start=1):
        assert offset == cursor
        assert page.tag(num).offset == offset
        assert page.tag(num).size == size
        cursor += size

    assert_page_matches_oracle(page, expected)


def test_large_page_uses_wide_tag_fields() -> None:
    # A 15-bit size and an offset above 0x1FFF are impossible with the small page encoding.
    large_node = NodeSpec(prefix_ref=4, key_suffix=b"", data=b"x" * 9000)
    trailing = NodeSpec(key_suffix=b"z", data=b"tail")
    spec = PageSpec(page_size=LARGE_PAGE, prefix=b"large-prefix", nodes=[large_node, trailing])
    raw, positions = encode_page(spec)
    page = parse_page(LARGE_PAGE, raw)

    assert positions[0][1] > SMALL_MASK
    assert positions[1][0] > SMALL_MASK
    assert page.tag(1).size == positions[0][1]
    assert page.tag(2).offset == positions[1][0]
    assert len(page.node(0).data) == 9000
    assert page.node(0).key == b"larg"

    assert_page_matches_oracle(page, oracle_page(raw, LARGE_PAGE))


@pytest.mark.parametrize("page_size", [SMALL_PAGE, LARGE_PAGE])
def test_common_prefix_and_private_suffix_reconstruction(page_size: int) -> None:
    prefix = b"prefix-and-more"
    spec = PageSpec(
        page_size=page_size,
        prefix=prefix,
        nodes=[
            NodeSpec(prefix_ref=0, key_suffix=b"alpha", data=b"0000"),
            NodeSpec(prefix_ref=5, key_suffix=b"beta", data=b"D1"),
            NodeSpec(prefix_ref=len(prefix), key_suffix=b"", data=b"FULL"),
            NodeSpec(key_suffix=b"gamma", data=b"private"),
        ],
    )
    raw, _ = encode_page(spec)
    page = parse_page(page_size, raw)

    assert page.key_prefix == prefix
    assert [(node.key_prefix, node.key_suffix, node.key) for node in page.nodes()] == [
        (b"", b"alpha", b"alpha"),
        (prefix[:5], b"beta", prefix[:5] + b"beta"),
        (prefix, b"", prefix),
        (b"", b"gamma", b"gamma"),
    ]
    assert [node.data for node in page.nodes()] == [b"0000", b"D1", b"FULL", b"private"]

    assert_page_matches_oracle(page, oracle_page(raw, page_size))


@pytest.mark.parametrize("page_size", [SMALL_PAGE, LARGE_PAGE])
def test_random_access_matches_sequential_walk_and_btree(page_size: int) -> None:
    prefix = b"co"
    keys = [b"alpha", b"coavo", b"delta", b"echo"]
    spec = PageSpec(
        page_size=page_size,
        prefix=prefix,
        nodes=[
            NodeSpec(key_suffix=keys[0], data=b"v0"),
            NodeSpec(prefix_ref=2, key_suffix=keys[1][2:], data=b"v1"),
            NodeSpec(prefix_ref=0, key_suffix=keys[2], data=b"v2"),
            NodeSpec(key_suffix=keys[3], data=b"v3"),
        ],
    )
    raw, _ = encode_page(spec)
    page = parse_page(page_size, bytes(raw))
    expected = oracle_page(bytes(raw), page_size)

    sequential = list(page.nodes())
    assert list(page.iter_leaf_nodes()) == sequential

    for num in range(page.node_count):
        for _ in range(3):  # Page caches nodes; verify the cache never changes an answer
            direct = page.node(num)
            assert direct.key == expected.nodes[num].key
            assert direct.data == expected.nodes[num].data
            assert direct.tag.offset == expected.nodes[num].offset
            assert direct.tag.size == expected.nodes[num].size

    for num, node in enumerate(sequential):
        assert node.key == keys[num]
        assert node.data == expected.nodes[num].data

    # Sequential traversal through nodes() and next() must agree with random access.
    btree = BTree(FakeDB(page_size), page)
    traversed = [btree.node()] + [btree.next() for _ in range(page.node_count - 1)]
    assert [node.key for node in traversed] == keys
    with pytest.raises(NoNeighbourPageError):
        btree.next()

    # BTree binary search must also land on the same node each key belongs to.
    for num, key in enumerate(keys):
        found = BTree(FakeDB(page_size), page).search(key, exact=True)
        assert found.key == key
        assert found.data == expected.nodes[num].data
        assert found.tag.offset == expected.nodes[num].offset


def test_rejects_tag_past_page_body() -> None:
    spec = basic_spec(SMALL_PAGE)
    raw, positions = encode_page(spec)
    # Extend the LAST node past ibMicFree: that is the page data boundary.
    last_node = len(spec.nodes)
    offset, size = positions[-1]
    pos = tag_position(SMALL_PAGE, last_node)
    struct.pack_into("<HH", raw, pos, size + 1, offset)

    page = parse_page(SMALL_PAGE, bytes(raw))
    with pytest.raises(InvalidPage, match="extends beyond the page body"):
        page.node(last_node - 1)


def test_rejects_tag_offset_past_page_body() -> None:
    spec = basic_spec(SMALL_PAGE)
    raw, _ = encode_page(spec)
    body_end = len(spec.prefix) + sum(len(encode_node(node, True)) for node in spec.nodes)
    pos = tag_position(SMALL_PAGE, 1)
    struct.pack_into("<HH", raw, pos, 4, body_end + 4)

    page = parse_page(SMALL_PAGE, bytes(raw))
    with pytest.raises(InvalidPage, match="extends beyond the page body"):
        page.node(0)


def test_rejects_tag_at_the_tag_array_boundary() -> None:
    spec = basic_spec(SMALL_PAGE)
    raw, _ = encode_page(spec)
    tag_count = len(spec.nodes) + 1
    tag_array_start = SMALL_PAGE - tag_count * 4

    # Grow the data area exactly up to the tag array. This is the closest a valid page can place
    # its data boundary without overlapping the tags.
    struct.pack_into("<H", raw, 32, tag_array_start - data_start(SMALL_PAGE))
    page = parse_page(SMALL_PAGE, bytes(raw))
    data_len = len(page.data)
    assert data_start(SMALL_PAGE) + data_len == tag_array_start

    # A tag offset at the first byte of the tag array must be rejected instead of reading tags as node data.
    last = tag_count - 1
    struct.pack_into("<HH", raw, tag_position(SMALL_PAGE, last), 4, data_len)
    with pytest.raises(InvalidPage, match="extends beyond the page body"):
        parse_page(SMALL_PAGE, bytes(raw)).node(last - 1)


def test_rejects_tag_array_overlapping_data() -> None:
    spec = basic_spec(SMALL_PAGE)
    raw, _ = encode_page(spec)
    header = c_esedb.PGHDR(raw)
    tag_array_start = SMALL_PAGE - (header.itagState & 0xFFF) * 4
    struct.pack_into("<H", raw, 32, tag_array_start - data_start(SMALL_PAGE) + 1)

    with pytest.raises(InvalidPage, match="tag array overlaps"):
        parse_page(SMALL_PAGE, bytes(raw))


def test_rejects_tag_count_outside_page() -> None:
    spec = basic_spec(SMALL_PAGE)
    raw, _ = encode_page(spec)
    header = c_esedb.PGHDR(raw)
    struct.pack_into("<H", raw, 34, (header.itagState & 0xF000) | 0x0FFF)

    with pytest.raises(InvalidPage, match="tag array overlaps"):
        parse_page(SMALL_PAGE, bytes(raw))


@pytest.mark.parametrize("page_size", [SMALL_PAGE, LARGE_PAGE])
def test_rejects_prefix_reference_past_common_prefix(page_size: int) -> None:
    spec = PageSpec(page_size=page_size, prefix=b"tiny", nodes=[NodeSpec(prefix_ref=5, key_suffix=b"k", data=b"v")])
    raw, _ = encode_page(spec)
    page = parse_page(page_size, raw)

    with pytest.raises(InvalidPage, match="prefix reference exceeds"):
        page.node(0)


def test_rejects_compressed_node_on_root_page() -> None:
    spec = PageSpec(
        page_size=SMALL_PAGE,
        flags=PAGE_FLAG.Root | PAGE_FLAG.Leaf,
        nodes=[NodeSpec(prefix_ref=0, key_suffix=b"k", data=b"v")],
    )
    raw, _ = encode_page(spec)
    page = parse_page(SMALL_PAGE, raw)

    with pytest.raises(InvalidPage, match="page has none"):
        page.node(0)


@pytest.mark.parametrize("page_size", [SMALL_PAGE, LARGE_PAGE])
@pytest.mark.parametrize("compressed", [False, True])
def test_rejects_suffix_length_past_tag_data(page_size: int, compressed: bool) -> None:
    prefix_ref = 2 if compressed else None
    spec = PageSpec(
        page_size=page_size,
        prefix=b"pp",
        nodes=[NodeSpec(prefix_ref=prefix_ref, key_suffix=b"key", data=b"payload")],
    )
    raw, positions = encode_page(spec)
    offset, _ = positions[0]
    word_offset = data_start(page_size) + offset + (2 if compressed else 0)
    struct.pack_into("<H", raw, word_offset, 0x1FFF)

    page = parse_page(page_size, bytes(raw))
    with pytest.raises(InvalidPage, match="suffix extends beyond tag data"):
        page.node(0)


def test_rejects_short_prefix_reference() -> None:
    # On small pages the compressed flag lives in the tag offset word, so one body byte can still be
    # marked as a compressed node that has no room for its prefix reference.
    spec = PageSpec(page_size=SMALL_PAGE, prefix=b"p", nodes=[NodeSpec(prefix_ref=0, key_suffix=b"", data=b"")])
    raw, _ = encode_page(spec)
    struct.pack_into("<HH", raw, tag_position(SMALL_PAGE, 1), 1, TAG_FLAG.Compressed << 13)
    with pytest.raises(InvalidPage, match="too small to contain a key prefix reference"):
        parse_page(SMALL_PAGE, bytes(raw)).node(0)


@pytest.mark.parametrize("page_size", [SMALL_PAGE, LARGE_PAGE])
def test_rejects_short_suffix_and_branch_payloads(page_size: int) -> None:

    # One byte where the suffix length belongs.
    spec = PageSpec(page_size=page_size, nodes=[NodeSpec(key_suffix=b"", data=b"")])
    raw, _ = encode_page(spec)
    struct.pack_into("<HH", raw, tag_position(page_size, 1), 1, 0)
    with pytest.raises(InvalidPage, match="too small to contain a key suffix length"):
        parse_page(page_size, bytes(raw)).node(0)

    # A branch node whose key consumes all but three bytes leaves no child page number.
    spec = PageSpec(page_size=page_size, flags=0, nodes=[NodeSpec(key_suffix=b"k", data=b"\x01\x02\x03")])
    raw, _ = encode_page(spec)
    with pytest.raises(InvalidPage, match="too small to contain a child page number"):
        parse_page(page_size, bytes(raw)).node(0)


def test_rejects_zero_size_node_tag() -> None:
    spec = basic_spec(SMALL_PAGE)
    raw, _ = encode_page(spec)
    struct.pack_into("<H", raw, tag_position(SMALL_PAGE, 1), 0)
    with pytest.raises(ValueError, match="Invalid TAG data"):
        parse_page(SMALL_PAGE, bytes(raw)).node(0)


def mutate_offset(rng: random.Random, raw: bytearray, base: PageSpec, node_idx: int, num: int) -> None:
    pos = tag_position(base.page_size, num)
    cb, ib = struct.unpack_from("<HH", raw, pos)
    new_offset = rng.randrange(0, base.page_size + 32) & tag_mask(base.page_size)
    struct.pack_into("<HH", raw, pos, cb, new_offset)


def mutate_size(rng: random.Random, raw: bytearray, base: PageSpec, node_idx: int, num: int) -> None:
    pos = tag_position(base.page_size, num)
    cb, ib = struct.unpack_from("<HH", raw, pos)
    new_size = rng.randrange(0, base.page_size + 32) & tag_mask(base.page_size)
    struct.pack_into("<HH", raw, pos, new_size, ib)


def mutate_flags(rng: random.Random, raw: bytearray, base: PageSpec, node_idx: int, num: int) -> None:
    flags = rng.randrange(0, 8)
    if is_small(base.page_size):
        pos = tag_position(base.page_size, num)
        cb, ib = struct.unpack_from("<HH", raw, pos)
        struct.pack_into("<HH", raw, pos, cb, (ib & SMALL_MASK) | (flags << 13))
    else:
        offset = struct.unpack_from("<H", raw, tag_position(base.page_size, num))[0] & LARGE_MASK
        body_start = data_start(base.page_size) + offset
        if body_start + 2 <= len(raw):
            word = struct.unpack_from("<H", raw, body_start)[0]
            struct.pack_into("<H", raw, body_start, (word & SMALL_MASK) | (flags << 13))


def mutate_prefix(rng: random.Random, raw: bytearray, base: PageSpec, node_idx: int, num: int) -> None:
    if base.nodes[node_idx].prefix_ref is None:
        return
    offset = struct.unpack_from("<H", raw, tag_position(base.page_size, num))[0] & tag_mask(base.page_size)
    body_start = data_start(base.page_size) + offset
    if body_start + 2 > len(raw):
        return
    word = struct.unpack_from("<H", raw, body_start)[0]
    struct.pack_into("<H", raw, body_start, (word & 0xE000) | (rng.randrange(0, len(base.prefix) + 8) & SMALL_MASK))


def mutate_suffix(rng: random.Random, raw: bytearray, base: PageSpec, node_idx: int, num: int) -> None:
    offset = struct.unpack_from("<H", raw, tag_position(base.page_size, num))[0] & tag_mask(base.page_size)
    body_start = data_start(base.page_size) + offset
    word_offset = body_start + (2 if base.nodes[node_idx].prefix_ref is not None else 0)
    if word_offset + 2 > len(raw):
        return
    word = struct.unpack_from("<H", raw, word_offset)[0]
    struct.pack_into("<H", raw, word_offset, (word & 0xE000) | (rng.randrange(0, base.page_size) & SMALL_MASK))


def mutate_tag_count(rng: random.Random, raw: bytearray, base: PageSpec, node_idx: int, num: int) -> None:
    state = read_u16(raw, 34)
    struct.pack_into("<H", raw, 34, (state & 0xF000) | (rng.randrange(0, 0x1000)))


def mutate_data_size(rng: random.Random, raw: bytearray, base: PageSpec, node_idx: int, num: int) -> None:
    struct.pack_into("<H", raw, 32, rng.randrange(0, base.page_size + 32))


MUTATORS = (
    mutate_offset,
    mutate_size,
    mutate_flags,
    mutate_prefix,
    mutate_suffix,
    mutate_tag_count,
    mutate_data_size,
)


@pytest.mark.parametrize("page_size", [SMALL_PAGE, LARGE_PAGE])
@pytest.mark.parametrize("leaf", [True, False])
@pytest.mark.parametrize("seed", FUZZ_SEEDS)
def test_fuzz_mutations_are_exact_or_explicitly_rejected(page_size: int, leaf: bool, seed: int) -> None:
    """Seed-driven differential fuzzing: every page is either fully exact or rejected."""
    rng = random.Random(seed ^ page_size ^ int(leaf))
    base = basic_spec(page_size, leaf=leaf)
    stats = {"accepted": 0, "rejected": 0}

    for _ in range(FUZZ_ITERATIONS):
        raw, _ = encode_page(base)
        node_idx = rng.randrange(len(base.nodes))
        rng.choice(MUTATORS)(rng, raw, base, node_idx, node_idx + 1)  # type: ignore[operator]

        try:
            expected = oracle_page(bytes(raw), page_size)
        except OracleInvalid:
            expected = None

        if expected is None:
            with pytest.raises((InvalidPage, ValueError, IndexError)):
                page = parse_page(page_size, bytes(raw))
                for num in range(page.node_count):
                    page.node(num)
            stats["rejected"] += 1
            continue

        page = parse_page(page_size, bytes(raw))
        assert_page_matches_oracle(page, expected)

        # Random access must return the same node objects the sequential walk produced.
        sequential = list(page.nodes())
        for num in range(page.node_count):
            direct = page.node(num)
            assert direct.key == sequential[num].key
            assert direct.data == sequential[num].data
            assert direct.tag.offset == sequential[num].tag.offset
            assert direct.tag.size == sequential[num].tag.size

        # Accepted leaf pages that are still sorted must let binary search find each key on its own node.
        # Unsorted pages can be legal for non-unique indexes, so ordering is checked before using search().
        # Branch pages would need their children loaded, so their key/child pairing is covered above instead.
        keys = [item.key for item in expected.nodes]
        if page.is_leaf and all(left < right for left, right in zip(keys, keys[1:], strict=False)):
            for item in expected.nodes:
                found = BTree(FakeDB(page_size), page).search(item.key, exact=True)
                assert found.key == item.key
                assert found.data == item.data

        stats["accepted"] += 1

    assert stats["accepted"] > 0
    assert stats["rejected"] > 0


def test_truncated_node_never_reassigns_the_key() -> None:
    """If a tag's declared size cuts a node short, reject it instead of returning a truncated key.

    This is the association bug: the parser used to take whatever bytes a Python slice returned.
    A short slice could still parse if the suffix length fit, yielding a different key for the same node.
    """
    spec = PageSpec(
        page_size=SMALL_PAGE,
        nodes=[NodeSpec(key_suffix=b"abcdef", data=b"payload")],
    )
    raw, positions = encode_page(spec)
    offset, size = positions[0]

    # Keep the offset, but declare only 4 bytes of the body. That leaves 2 bytes for the length word and
    # 1 byte of the 6-byte suffix. The old parser would accept b"a" as the key and move on.
    struct.pack_into("<HH", raw, tag_position(SMALL_PAGE, 1), 4, offset)

    with pytest.raises(InvalidPage, match="suffix extends beyond tag data"):
        parse_page(SMALL_PAGE, bytes(raw)).node(0)

    # The untouched layout still yields the full six-byte key and full payload.
    intact_raw, _ = encode_page(spec)
    intact = parse_page(SMALL_PAGE, bytes(intact_raw)).node(0)
    assert intact.key == b"abcdef"
    assert intact.data == b"payload"


def test_valid_contiguous_layout_is_not_confused_by_adjacent_slices() -> None:
    """Adjacent node bodies must never share bytes when reconstructed correctly."""
    spec = PageSpec(
        page_size=SMALL_PAGE,
        prefix=b"",
        nodes=[
            NodeSpec(key_suffix=b"aa", data=b"X"),
            NodeSpec(key_suffix=b"bb", data=b"Y"),
        ],
    )
    raw, positions = encode_page(spec)
    page = parse_page(SMALL_PAGE, bytes(raw))

    assert [node.key for node in page.nodes()] == [b"aa", b"bb"]
    assert [node.data for node in page.nodes()] == [b"X", b"Y"]
    # The end of node 0 is exactly the start of node 1, and neither read leaks across that line.
    assert positions[1][0] == positions[0][0] + positions[0][1]


def test_fixture_record_traversal_still_works(basic_db: BinaryIO) -> None:
    """A regression guard: strict parsing must not reject a valid database's actual record walk."""
    db = EseDB(basic_db)
    table = db.table("basic")

    records = list(table.records())
    assert len(records) == 2
    assert [record.Id for record in records] == [1, 2]
