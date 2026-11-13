from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from dissect.esedb.btree import BTree, BTreePosition
from dissect.esedb.exceptions import NoNeighbourPageError
from dissect.esedb.record import Record

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.esedb.c_esedb import RecordValue
    from dissect.esedb.index import Index
    from dissect.esedb.page import Node


class CursorPosition(NamedTuple):
    """An immutable snapshot of a :class:`Cursor` position.

    This captures the position of the primary index tree and, for a secondary index cursor, the position of the
    primary table tree used for record lookups. It is a snapshot of traversal state only: all trees keep sharing
    the cached, immutable pages of the :class:`~dissect.esedb.esedb.EseDB` instance, so no database data is copied.
    """

    primary: BTreePosition
    secondary: BTreePosition | None


class Cursor:
    """A simple cursor implementation for searching the ESE indexes.

    A cursor owns its traversal state in the index tree (and, for secondary indexes, in the primary table tree
    used to resolve records). The explicit :meth:`next`, :meth:`prev`, :meth:`search`, :meth:`seek` and
    :meth:`reset` methods keep operating on this cursor's current position.

    Traversals that need to outlive an interleaved query never move this cursor: iterating the cursor
    (:meth:`__iter__`) and :meth:`find_all` run on a :meth:`fork` of the cursor with its own stable position, and
    resolving a secondary index entry uses a throwaway fork of the primary table tree. Use :meth:`position` and
    :meth:`restore` to capture and reapply a position directly.

    Args:
        index: The :class:`~dissect.esedb.index.Index` to create the cursor for.
    """

    def __init__(self, index: Index):
        self.index = index
        self.table = index.table
        self.esedb = index.esedb

        self._primary = BTree(self.esedb, index.root)
        self._secondary = None if index.is_primary else BTree(self.esedb, self.table.root)

    def __iter__(self) -> Iterator[Record]:
        # Iterate on a fork so that consuming the iterator (and any interleaved queries on this cursor) cannot
        # move this cursor's position. The fork starts at the current position.
        traversal = self.fork()
        # A fresh cursor is positioned on the root page; descend to the first leaf node before walking. A cursor
        # that was already positioned on a leaf (for example by a search) keeps that position.
        if not traversal._primary.is_leaf:
            traversal._primary.first()
        while True:
            yield traversal._record()

            try:
                traversal._primary.next()
            except NoNeighbourPageError:
                break

    def fork(self) -> Cursor:
        """Create an independent cursor over the same index at the current position.

        The returned cursor shares this cursor's index, table and (cached, immutable) pages but has its own
        traversal state. Moving the fork never moves this cursor and vice versa. No page data is copied.
        """
        fork = Cursor(self.index)
        fork.restore(self.position())
        return fork

    def position(self) -> CursorPosition:
        """Return an immutable snapshot of the current position.

        The snapshot only covers traversal positions (the primary index tree, and the primary table tree for a
        secondary index). Page data is not copied; restore it with :meth:`restore` on a cursor of the same index
        on the same :class:`~dissect.esedb.esedb.EseDB` instance.
        """
        secondary = self._secondary.position() if self._secondary else None
        return CursorPosition(self._primary.position(), secondary)

    def restore(self, position: CursorPosition) -> None:
        """Restore a position previously returned by :meth:`position`.

        Args:
            position: The position to restore.
        """
        self._primary.restore(position.primary)
        if self._secondary and position.secondary:
            self._secondary.restore(position.secondary)

    def _node(self) -> Node:
        """Return the node the cursor is currently on. Resolves the secondary index if needed.

        Resolving a secondary index entry performs an exact search in the primary table tree. This runs on a
        throwaway fork so that this lookup never changes the primary table position held by any other traversal.

        Returns:
            A :class:`~dissect.esedb.page.Node` object of the current node.
        """
        node = self._primary.node()
        if self._secondary:
            lookup = self._secondary.fork()
            lookup.reset()
            node = lookup.search(node.data.tobytes(), exact=True)
        return node

    def _record(self) -> Record:
        """Return the record the cursor is currently on.

        Returns:
            A :class:`~dissect.esedb.record.Record` object of the current record.
        """
        return Record(self.table, self._node())

    def reset(self) -> None:
        """Reset the internal state."""
        self._primary.reset()
        if self._secondary:
            self._secondary.reset()

    def search(self, **kwargs: RecordValue) -> Record:
        """Search the index for the requested values.

        Searching modifies the cursor state. Searching again will search from the current position.
        Reset the cursor with :meth:`reset` to start from the beginning.

        Args:
            **kwargs: The columns and values to search for.

        Returns:
            A :class:`~dissect.esedb.record.Record` object of the found record.
        """
        key = self.index.make_key(kwargs)
        return self.search_key(key, exact=True)

    def search_key(self, key: bytes, exact: bool = True) -> Record:
        """Search for a record with the given ``key``.

        Args:
            key: The key to search for.
            exact: If ``True``, search for an exact match. If ``False``, sets the cursor on the
                   next record that is greater than or equal to the key.
        """
        self._primary.search(key, exact)
        return self._record()

    def seek(self, **kwargs: RecordValue) -> None:
        """Seek to the record with the given values.

        Args:
            **kwargs: The columns and values to seek to.
        """
        key = self.index.make_key(kwargs)
        self.search_key(key, exact=False)

    def seek_key(self, key: bytes) -> None:
        """Seek to the record with the given ``key``.

        Args:
            key: The key to seek to.
        """
        self._primary.search(key, exact=False)

    def find(self, **kwargs: RecordValue) -> Record | None:
        """Find a record in the index.

        This differs from :meth:`search` in that it will allow additional filtering on non-indexed columns.

        This runs on a fork of the cursor, so neither the lookup nor the filtering moves this cursor's position.

        Args:
            **kwargs: The columns and values to search for.
        """
        return next(self.find_all(**kwargs), None)

    def find_all(self, **kwargs: RecordValue) -> Iterator[Record]:
        """Find all records in the index that match the given values.

        This differs from :meth:`search` in that it will allows additional filtering on non-indexed columns.
        If you only search on indexed columns, this will yield all records that match the indexed columns.

        The traversal runs on a :meth:`fork` that is created when iteration starts. The initial exact search,
        walking back over duplicate keys that span leaf pages, advancing through the matches and filtering on
        non-indexed columns all happen on that fork, so this generator never moves this cursor's position and
        multiple generators can interleave without affecting each other. Closing the generator early simply
        discards the fork.

        Args:
            **kwargs: The columns and values to search for.
        """
        # Defer forking until the generator is started so the position snapshot matches the start of iteration
        traversal = self.fork()

        indexed_columns = {c.name: kwargs.pop(c.name) for c in traversal.index.columns}
        other_columns = kwargs

        # A find_all spans the entire index: start the fork from the tree root so the exact search can descend
        # to any leaf, regardless of the position this cursor was forked from.
        traversal._primary.reset()
        # We need at least an exact match on the indexed columns
        traversal.search(**indexed_columns)

        current_key = traversal._primary.node().key

        # Check if we need to move the cursor back to find the first record
        while True:
            if current_key != traversal._primary.node().key:
                traversal._primary.next()
                break

            try:
                traversal._primary.prev()
            except NoNeighbourPageError:
                break

        while True:
            # Entries with the same indexed columns are guaranteed to be adjacent
            if current_key != traversal._primary.node().key:
                break

            record = traversal._record()
            for k, v in other_columns.items():
                value = record.get(k)
                # If the record value is a list, we do a check based on the queried value
                if isinstance(value, list):
                    # If the queried value is also a list, we check if they are equal
                    if isinstance(v, list):
                        if value != v:
                            break
                    # Otherwise we check if the queried value is in the record value
                    elif v not in value:
                        break
                else:
                    if value != v:
                        break
            else:
                yield record

            try:
                traversal._primary.next()
            except NoNeighbourPageError:
                break

    def record(self) -> Record:
        """Return the record the cursor is currently on.

        Returns:
            A :class:`~dissect.esedb.record.Record` object of the current record.
        """
        return self._record()

    def next(self) -> Record:
        """Move the cursor to the next record and return it.

        Can move the cursor to the next page as a side effect.

        Returns:
            A :class:`~dissect.esedb.record.Record` object of the next record.
        """
        try:
            self._primary.next()
        except NoNeighbourPageError:
            raise IndexError("No next record")
        return self._record()

    def prev(self) -> Record:
        """Move the cursor to the previous node and return it.

        Can move the cursor to the previous page as a side effect.

        Returns:
            A :class:`~dissect.esedb.record.Record` object of the previous record.
        """
        try:
            self._primary.prev()
        except NoNeighbourPageError:
            raise IndexError("No previous record")
        return self._record()
