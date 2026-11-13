"""Assertions for the controlled collation experiments in ``experiments/``.

These tests pin down the difference between three relations that forensic
tooling must not conflate:

* raw stored bytes equality,
* Python ``str ==``,
* ESE normalized sort-key equality (the actual cursor matching rule).

They exercise only production encoder behaviour through the experiment
harness; no library collation code is modified.
"""

from __future__ import annotations

from dissect.esedb.btree import find_node
from dissect.esedb.lcmapstring import MapFlags

from experiments.run_key_equivalence import (
    E_ACUTE,
    E_COMBINING,
    experiment_accent_distinction,
    experiment_ascii_branch,
    experiment_composite_and_truncation,
    experiment_normalization_is_not_python_equality,
    experiment_unicode_single_column,
)
from experiments.sim_esedb import (
    DEFAULT_LCMAP_FLAGS,
    SimulatedIndex,
    long_column,
    unicode_column,
    utf16,
)
from experiments.validate_on_fixtures import (
    validate_rebuilt_keys_match_disk,
    validate_ual_duplicate_keys,
)


def test_case_folds_to_one_key_but_distinct_raw_bytes() -> None:
    index = SimulatedIndex([unicode_column("Name")])
    lower = index.insert(1, {"Name": "abc"}, {"Name": utf16("abc")})
    upper = index.insert(2, {"Name": "ABC"}, {"Name": utf16("ABC")})

    assert lower.key == upper.key
    assert lower.raw["Name"] != upper.raw["Name"]
    assert "abc" != "ABC"
    assert {r.record_id for r in index.exact_search({"Name": "ABC"})} == {1, 2}


def test_full_width_and_half_width_are_equivalent() -> None:
    index = SimulatedIndex([unicode_column("Name")])
    half = index.make_key({"Name": "ABC"})
    full = index.make_key({"Name": "ＡＢＣ"})
    assert half == full
    assert utf16("ABC") != utf16("ＡＢＣ")


def test_trailing_nul_is_unsortable_and_equivalent() -> None:
    index = SimulatedIndex([unicode_column("Name")])
    assert index.make_key({"Name": "abc"}) == index.make_key({"Name": "abc\x00"})


def test_accents_remain_distinct_by_default() -> None:
    index = SimulatedIndex([unicode_column("Name")])
    plain = index.make_key({"Name": "e"})
    accented = index.make_key({"Name": E_ACUTE})
    assert plain != accented

    insensitive = SimulatedIndex(
        [unicode_column("Name")],
        lcmap_flags=DEFAULT_LCMAP_FLAGS | MapFlags.NORM_IGNORENONSPACE,
    )
    assert insensitive.make_key({"Name": "e"}) == insensitive.make_key({"Name": E_ACUTE})


def test_combining_sequence_is_not_folded_by_this_implementation() -> None:
    index = SimulatedIndex([unicode_column("Name")])
    precomposed = index.make_key({"Name": E_ACUTE})
    combining = index.make_key({"Name": E_COMBINING})
    assert E_ACUTE != E_COMBINING
    assert precomposed != combining


def test_composite_key_truncation_collapses_later_column() -> None:
    index = SimulatedIndex([unicode_column("Name"), long_column("Num")], key_most=20)
    first = index.insert(
        1, {"Name": "abcdefghijklmnop", "Num": 7},
        {"Name": utf16("a" * 16)}, payload={"Status": "first"},
    )
    second = index.insert(
        2, {"Name": "ABCDEFGHIJKLMNOP", "Num": 999},
        {"Name": utf16("b" * 16)}, payload={"Status": "second"},
    )
    assert first.key == second.key

    hits = index.exact_search({"Name": "AbCdEfGhIjKlMnOp", "Num": 123456})
    assert {r.record_id for r in hits} == {1, 2}
    # The later, non-index-comparable payload still differs between the rows.
    assert {r.payload["Status"] for r in hits} == {"first", "second"}


def test_equal_sort_key_keeps_distinct_later_columns() -> None:
    index = SimulatedIndex([unicode_column("Name")])
    index.insert(1, {"Name": "abc"}, {"Name": utf16("abc")}, payload={"Tag": "x"})
    index.insert(2, {"Name": "ABC"}, {"Name": utf16("ABC")}, payload={"Tag": "y"})
    hits = index.exact_search({"Name": "abc"})
    assert len(hits) == 2
    assert {r.payload["Tag"] for r in hits} == {"x", "y"}


def test_experiment_report_functions() -> None:
    summary = experiment_unicode_single_column()
    lowercase_hits = next(
        q["hit_ids"] for q in summary["queries"] if q["label"] == "lowercase query"
    )
    assert set(lowercase_hits) == {1, 3, 6}
    nfd_hits = next(q["hit_ids"] for q in summary["queries"] if q["label"] == "NFD query")
    assert nfd_hits == [2]

    assert experiment_accent_distinction() == {
        "default_equal": False, "ignore_nonspace_equal": True
    }
    assert experiment_ascii_branch()["key_equal"] is True

    composite = experiment_composite_and_truncation()
    assert composite["truncated_equal"] is True
    assert composite["untruncated_equal"] is False

    table = experiment_normalization_is_not_python_equality()["table"]
    by_label = {row["label"]: row for row in table}
    assert by_label["case"] == {
        "label": "case", "raw_equal": False, "python_equal": False, "db_key_equal": True
    }
    assert by_label["accent"]["db_key_equal"] is False


def test_rebuilt_keys_match_on_disk_nodes() -> None:
    report = validate_rebuilt_keys_match_disk()
    assert report
    assert all(mismatches == 0 for _, _, mismatches in report)
    assert sum(total for _, total, _ in report) >= 4


def test_ual_fixture_duplicate_normalized_key() -> None:
    info = validate_ual_duplicate_keys()
    assert info["equal_leaf_count"] == 5
    assert info["find_all_count"] == 5
    assert len(info["distinct_primary_keys"]) == 5
    # find_node is not bisect_left over duplicate keys; find_all compensates.
    assert info["landing_is_first"] is False
    assert info["find_node_landing"] in info["equal_key_indices"]
    # Indexed text columns match by collation even with changed casing; the
    # non-indexed later-column filter is plain Python equality.
    assert info["case_changed_hits"] == 5
    assert info["non_index_filtered_hits"] == 1


def test_find_node_duplicates_land_within_equal_run() -> None:
    class FakeNode:
        def __init__(self, num: int, key: bytes):
            self.num = num
            self.key = key
            self.child = None

    class FakePage:
        is_branch = False

        def __init__(self, keys: list[bytes]):
            self.node_count = len(keys)
            self._keys = keys

        def node(self, i: int) -> FakeNode:
            return FakeNode(i, self._keys[i])

    equal_run = [1, 2, 3, 4, 5]
    page = FakePage([b"a", b"b", b"b", b"b", b"b", b"b", b"c"])
    assert find_node(page, b"b").num in equal_run
