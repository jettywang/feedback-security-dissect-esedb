from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

import pytest

import dissect.esedb.cursor as cursor_module
from dissect.esedb.btree import BTree, BTreePosition
from dissect.esedb.cursor import Cursor, CursorPosition
from dissect.esedb.exceptions import KeyNotFoundError, NoNeighbourPageError

if TYPE_CHECKING:
    from dissect.esedb.index import Index
    from dissect.esedb.page import Node


class FakeNode:
    """Minimal stand-in for :class:`~dissect.esedb.page.Node` used by :class:`BTree` and :class:`Cursor`."""

    def __init__(self, key: bytes, data: bytes = b"", child: int | None = None):
        self.num = 0
        self.key = key
        # BTree/Cursor only need a buffer-like object (``.tobytes()`` is used for secondary index lookups)
        self.data = memoryview(data)
        self.child = child


class FakePage:
    """Minimal stand-in for :class:`~dissect.esedb.page.Page`.

    Pages are shared, effectively immutable objects, mirroring how real pages are cached on the EseDB instance.
    """

    def __init__(self, num: int, nodes: list[FakeNode], is_leaf: bool, prev: int = 0, nxt: int = 0):
        self.num = num
        self._nodes = nodes
        self.is_leaf = is_leaf
        self.is_branch = not is_leaf
        self.previous_page = prev
        self.next_page = nxt
        self.node_count = len(nodes)
        for i, node in enumerate(nodes):
            node.num = i

    def node(self, num: int) -> FakeNode:
        return self._nodes[num]

    def __repr__(self) -> str:
        kind = "leaf" if self.is_leaf else "branch"
        return f"<FakePage {self.num} {kind}>"


class FakeEseDB:
    """In-memory page cache with the same ``page`` lookup contract as :class:`~dissect.esedb.esedb.EseDB`."""

    def __init__(self):
        self._pages: dict[int, FakePage] = {}
        self.page = lru_cache(4096)(self._page)

    def add(self, page: FakePage) -> None:
        self._pages[page.num] = page

    def _page(self, num: int) -> FakePage:
        return self._pages[num]


def build_tree(
    esedb: FakeEseDB, entries: list[tuple[bytes, bytes]], leaf_capacity: int, start_page: int
) -> int:
    """Build a multi-level B+Tree from sorted ``(key, data)`` entries.

    Returns the root page number. Branch node keys are non-inclusive upper bounds, matching real ESE pages.
    """
    page_num = start_page
    leaf_pages = []
    for i in range(0, len(entries), leaf_capacity):
        chunk = entries[i : i + leaf_capacity]
        nodes = [FakeNode(key, data=data) for key, data in chunk]
        page = FakePage(page_num, nodes, is_leaf=True)
        esedb.add(page)
        leaf_pages.append(page)
        page_num += 1

    for i, page in enumerate(leaf_pages):
        page.previous_page = leaf_pages[i - 1].num if i > 0 else 0
        page.next_page = leaf_pages[i + 1].num if i + 1 < len(leaf_pages) else 0

    def first_key(page: FakePage) -> bytes:
        if page.is_leaf:
            return page.node(0).key
        return first_key(esedb.page(page.node(0).child))

    level = leaf_pages
    while len(level) > 1:
        parents = []
        for i in range(0, len(level), 2):
            children = level[i : i + 2]
            nodes = []
            for j, child in enumerate(children):
                if j + 1 < len(children):
                    # Non-inclusive upper bound: the first key of the next child
                    key = first_key(children[j + 1])
                else:
                    key = first_key(child)
                nodes.append(FakeNode(key, child=child.num))
            page = FakePage(page_num, nodes, is_leaf=False)
            esedb.add(page)
            parents.append(page)
            page_num += 1
        level = parents

    return level[0].num


class FakeColumn:
    def __init__(self, name: str):
        self.name = name


class FakeIndex:
    def __init__(
        self,
        table: "FakeTable",
        name: str,
        root_num: int,
        is_primary: bool,
        columns: list[FakeColumn],
    ):
        self.table = table
        self.esedb = table.esedb
        self.name = name
        self._root_num = root_num
        self.is_primary = is_primary
        self.columns = columns

    @property
    def root(self) -> FakePage:
        return self.esedb.page(self._root_num)

    def make_key(self, values: dict[str, str]) -> bytes:
        return next(iter(values.values())).encode()

    def cursor(self) -> Cursor:
        return Cursor(self)


class FakeTable:
    def __init__(self, esedb: FakeEseDB, root_num: int):
        self.esedb = esedb
        self.root = esedb.page(root_num)


class FakeRecord:
    """Record stand-in whose identity is the primary record key it resolves to."""

    def __init__(self, table: FakeTable, node: Node):
        self.table = table
        self.node = node
        self.identity = node.key.decode()

    def get(self, attr: str) -> str:
        return self.table.records[self.identity][attr]


class SecondaryTreeContext:
    """A multi-page primary tree plus a multi-page secondary index with cross-page duplicate keys."""

    RECORD_COUNT = 12
    GROUPS = 3

    def __init__(self, monkeypatch: pytest.MonkeyPatch):
        self.esedb = FakeEseDB()

        primary_entries = [(f"P{i:02d}".encode(), f"P{i:02d}".encode()) for i in range(self.RECORD_COUNT)]
        primary_root = build_tree(self.esedb, primary_entries, leaf_capacity=2, start_page=100)
        self.table = FakeTable(self.esedb, primary_root)
        self.table.records = {
            f"P{i:02d}": {"Group": f"G{i % self.GROUPS}", "Flag": "even" if i % 2 == 0 else "odd"}
            for i in range(self.RECORD_COUNT)
        }

        # Four records per group; with a leaf capacity of 3 each group's duplicates span multiple leaf pages
        secondary_entries = [
            (f"G{i % self.GROUPS}".encode(), f"P{i:02d}".encode()) for i in range(self.RECORD_COUNT)
        ]
        secondary_entries.sort(key=lambda entry: (entry[0], int(entry[1][1:])))
        secondary_root = build_tree(self.esedb, secondary_entries, leaf_capacity=3, start_page=200)
        self.secondary_order = [data.decode() for _, data in secondary_entries]
        self.group_members = {
            f"G{g}": [data.decode() for key, data in secondary_entries if key == f"G{g}".encode()]
            for g in range(self.GROUPS)
        }
        self.group_pages = {
            f"G{g}": {
                page.num
                for page in self.esedb._pages.values()
                if page.is_leaf and page.num >= 200
                for node in page._nodes
                if node.key == f"G{g}".encode()
            }
            for g in range(self.GROUPS)
        }

        self.index: Index = FakeIndex(self.table, "IxGroup", secondary_root, False, [FakeColumn("Group")])
        # Resolve records through the stand-in so record identity is observable
        monkeypatch.setattr(cursor_module, "Record", FakeRecord)

    def cursor(self) -> Cursor:
        return Cursor(self.index)


@pytest.fixture
def secondary_tree(monkeypatch: pytest.MonkeyPatch) -> SecondaryTreeContext:
    return SecondaryTreeContext(monkeypatch)


def test_btree_walks_multi_page_tree_in_both_directions() -> None:
    esedb = FakeEseDB()
    entries = [(f"K{i:02d}".encode(), b"") for i in range(12)]
    root = build_tree(esedb, entries, leaf_capacity=2, start_page=100)
    tree = BTree(esedb, root)

    assert not tree.is_leaf
    tree.first()
    forward = [tree.node().key]
    while True:
        try:
            forward.append(tree.next().key)
        except NoNeighbourPageError:
            break
    assert forward == [key for key, _ in entries]

    tree.last()
    backward = [tree.node().key]
    while True:
        try:
            backward.append(tree.prev().key)
        except NoNeighbourPageError:
            break
    assert backward == [key for key, _ in reversed(entries)]


def test_btree_fork_holds_independent_position() -> None:
    esedb = FakeEseDB()
    entries = [(f"K{i:02d}".encode(), b"") for i in range(12)]
    root = build_tree(esedb, entries, leaf_capacity=2, start_page=100)
    tree = BTree(esedb, root)
    tree.first()

    snapshot = tree.position()
    fork = tree.fork()
    while True:
        try:
            fork.next()
        except NoNeighbourPageError:
            break

    # Exhausting the fork must not move the original tree; the database and pages are shared
    assert tree.position() == snapshot
    assert tree.esedb is fork.esedb
    assert tree.root is fork.root
    assert tree.node() is not fork.node()


def test_btree_position_save_restore() -> None:
    esedb = FakeEseDB()
    entries = [(f"K{i:02d}".encode(), b"") for i in range(12)]
    root = build_tree(esedb, entries, leaf_capacity=2, start_page=100)
    tree = BTree(esedb, root)
    tree.search(b"K05", exact=True)
    saved = tree.position()
    assert isinstance(saved, BTreePosition)

    tree.next()
    assert tree.node().key == b"K06"
    tree.restore(saved)
    assert tree.position() == saved
    assert tree.node().key == b"K05"


def test_btree_failed_exact_search_keeps_position() -> None:
    esedb = FakeEseDB()
    entries = [(f"K{i:02d}".encode(), b"") for i in range(12)]
    root = build_tree(esedb, entries, leaf_capacity=2, start_page=100)
    tree = BTree(esedb, root)
    tree.search(b"K07", exact=True)
    before = tree.position()

    with pytest.raises(KeyNotFoundError):
        tree.search(b"KZZ", exact=True)

    assert tree.position() == before
    assert tree.node().key == b"K07"


def test_secondary_index_resolves_primary_record_identities(secondary_tree: SecondaryTreeContext) -> None:
    cursor = secondary_tree.cursor()
    identities = [record.identity for record in cursor]
    assert identities == secondary_tree.secondary_order


def test_duplicate_secondary_keys_span_leaf_pages(secondary_tree: SecondaryTreeContext) -> None:
    # Sanity check on the fixture: every group's duplicate key is split across leaf pages
    for pages in secondary_tree.group_pages.values():
        assert len(pages) > 1


def test_find_all_returns_complete_cross_page_duplicate_group(secondary_tree: SecondaryTreeContext) -> None:
    cursor = secondary_tree.cursor()
    for group, members in secondary_tree.group_members.items():
        assert [record.identity for record in cursor.find_all(Group=group)] == members


def test_find_all_filters_on_non_indexed_column(secondary_tree: SecondaryTreeContext) -> None:
    cursor = secondary_tree.cursor()
    expected = [
        identity
        for identity in secondary_tree.group_members["G0"]
        if secondary_tree.table.records[identity]["Flag"] == "even"
    ]
    assert [record.identity for record in cursor.find_all(Group="G0", Flag="even")] == expected


def test_find_all_does_not_move_cursor_position(secondary_tree: SecondaryTreeContext) -> None:
    cursor = secondary_tree.cursor()
    cursor.search(Group="G1")
    before = cursor.position()
    current_identity = cursor.record().identity

    list(cursor.find_all(Group="G0"))

    assert cursor.position() == before
    assert cursor.record().identity == current_identity


def test_interleaved_forward_and_backward_traversals_stay_independent(
    secondary_tree: SecondaryTreeContext,
) -> None:
    forward_cursor = secondary_tree.cursor()
    backward_cursor = secondary_tree.cursor()
    backward_cursor._primary.last()

    forward = iter(forward_cursor)
    backward = []
    expected_forward = secondary_tree.secondary_order
    expected_backward = list(reversed(secondary_tree.secondary_order))

    # Interleave one forward step with one backward step until the forward traversal is fully consumed
    for expected in expected_forward:
        assert next(forward).identity == expected
        backward.append(backward_cursor.record().identity)
        try:
            backward_cursor.prev()
        except IndexError:
            break

    # The backward traversal independently covered the full range with no omissions or duplicates
    assert backward == expected_backward
    assert len(backward) == len(set(backward))


def test_nested_exact_query_does_not_disturb_outer_traversal(secondary_tree: SecondaryTreeContext) -> None:
    outer = secondary_tree.cursor()
    outer_iter = iter(outer)

    seen = []
    for i, expected in enumerate(secondary_tree.secondary_order):
        record = next(outer_iter)
        assert record.identity == expected
        seen.append(record.identity)

        # An interleaved exact query on another cursor over the same index
        nested = secondary_tree.cursor()
        target_group = "G2" if i % 2 == 0 else "G1"
        nested_record = nested.search(Group=target_group)
        # A duplicate-key search lands on one of the matching entries; find_all defines the full ordered range
        assert nested_record.identity in secondary_tree.group_members[target_group]

    assert seen == secondary_tree.secondary_order


def test_nested_find_all_inside_find_all_is_isolated(secondary_tree: SecondaryTreeContext) -> None:
    outer_cursor = secondary_tree.cursor()
    outer = outer_cursor.find_all(Group="G0")

    collected = []
    for first in outer:
        collected.append(first.identity)
        # Nested traversal on a different group while the outer generator is suspended mid-range
        nested = [record.identity for record in outer_cursor.find_all(Group="G2")]
        assert nested == secondary_tree.group_members["G2"]

    assert collected == secondary_tree.group_members["G0"]
    assert len(collected) == len(set(collected))


def test_failed_search_does_not_disturb_other_traversal(secondary_tree: SecondaryTreeContext) -> None:
    traversal = secondary_tree.cursor()
    iterator = iter(traversal)
    first = next(iterator).identity

    other = secondary_tree.cursor()
    with pytest.raises(KeyNotFoundError):
        other.search(Group="GZZ")

    # The suspended traversal resumes exactly where it left off
    assert first == secondary_tree.secondary_order[0]
    assert [record.identity for record in iterator] == secondary_tree.secondary_order[1:]


def test_early_closed_iterator_leaves_other_traversals_intact(secondary_tree: SecondaryTreeContext) -> None:
    full_cursor = secondary_tree.cursor()
    full_iter = iter(full_cursor)
    next(full_iter)
    next(full_iter)

    short_cursor = secondary_tree.cursor()
    short_iter = iter(short_cursor)
    next(short_iter)
    short_iter.close()  # Abandon this traversal halfway

    remaining = [record.identity for record in full_iter]
    assert remaining == secondary_tree.secondary_order[2:]

    # A fresh traversal after the early close still returns the complete, deduplicated range
    fresh = [record.identity for record in secondary_tree.cursor()]
    assert fresh == secondary_tree.secondary_order
    assert len(fresh) == len(set(fresh))


def test_cursor_fork_and_position_restore(secondary_tree: SecondaryTreeContext) -> None:
    cursor = secondary_tree.cursor()
    cursor.search(Group="G1")
    saved = cursor.position()
    assert isinstance(saved, CursorPosition)
    assert saved.secondary is not None
    current_identity = cursor.record().identity

    fork = cursor.fork()
    fork.next()
    assert fork.position() != cursor.position()
    assert cursor.position() == saved

    cursor.next()
    cursor.restore(saved)
    assert cursor.position() == saved
    assert cursor.record().identity == current_identity


def test_secondary_lookup_does_not_mutate_shared_primary_tree(secondary_tree: SecondaryTreeContext) -> None:
    cursor = secondary_tree.cursor()
    assert cursor._secondary is not None
    secondary_saved = cursor._secondary.position()

    # Resolving records performs exact searches on throwaway forks of the primary table tree. Move onto leaf
    # nodes first (a fresh cursor starts on the root page).
    cursor._primary.first()
    for _ in range(4):
        cursor.record()
        cursor.next()

    assert cursor._secondary.position() == secondary_saved
