"""Controlled experiments for dissect.esedb text index key equivalence.

This package does not modify any library code. It reuses the production key
encoding functions (``dissect.esedb.index.encode_key`` / ``Index.make_key``)
and reproduces the on-disk comparison semantics described in
``dissect.esedb.btree.find_node`` (raw byte comparison of normalized keys).
"""
