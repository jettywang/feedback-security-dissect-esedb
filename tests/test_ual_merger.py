from __future__ import annotations

import datetime
import gzip
from itertools import permutations
from pathlib import Path
from typing import BinaryIO

from dissect.esedb.tools.ual_merger import (
    DATE_UNCERTAINTY_REASONS,
    REASON_COLLECTION_ORDER_UNKNOWN,
    REASON_COUNT_DECREASE,
    REASON_CROSS_YEAR_AMBIGUITY,
    REASON_DAY_OUT_OF_YEAR,
    REASON_LEAP_YEAR_AMBIGUITY,
    REASON_MULTIPLE_CANDIDATE_YEARS,
    REASON_NEGATIVE_INCREMENT_SUPPRESSED,
    REASON_NO_DELTA_FIRST_OBSERVATION,
    REASON_YEAR_BOUNDARY_MISSING,
    DayEvidence,
    MergedDayAccess,
    Snapshot,
    UALMerger,
    UALSnapshot,
    resolve_day_candidates,
)

UTC = datetime.timezone.utc
ENTITY = (("RoleGuid", "role-1"), ("Address", "10.0.0.1"))
TABLE = "CLIENTS"
DEFAULT_FIRST_SEEN = datetime.datetime(2020, 1, 5, tzinfo=UTC)
DEFAULT_LAST_ACCESS = datetime.datetime(2020, 6, 1, tzinfo=UTC)
DEFAULT_COLLECTED_AT = datetime.datetime(2020, 6, 2, tzinfo=UTC)
EntityKey = tuple[tuple[str, str | None], ...]


def dt(year: int, month: int, day: int) -> datetime.datetime:
    return datetime.datetime(year, month, day, tzinfo=UTC)


def make_evidence(
    source: str,
    day_num: int,
    count: int,
    first_seen: datetime.datetime | None = DEFAULT_FIRST_SEEN,
    last_access: datetime.datetime | None = DEFAULT_LAST_ACCESS,
    collected_at: datetime.datetime | None = DEFAULT_COLLECTED_AT,
    page: int | None = 10,
    tag: int | None = 1,
    entity_key: EntityKey = ENTITY,
) -> DayEvidence:
    candidates, reasons = resolve_day_candidates(day_num, first_seen, last_access, collected_at)
    return DayEvidence(
        source=source,
        table=TABLE,
        page=page,
        tag=tag,
        entity_key=entity_key,
        day_num=day_num,
        count=count,
        first_seen=first_seen,
        last_access=last_access,
        collected_at=collected_at,
        candidate_dates=tuple(candidates),
        reasons=tuple(reasons),
    )


def find_group(merger: UALMerger, date: datetime.datetime, entity_key: EntityKey = ENTITY) -> MergedDayAccess:
    matches = [
        result
        for result in merger.merge()
        if result.date == date and result.entity_key == entity_key and result.table == TABLE
    ]
    assert len(matches) == 1
    return matches[0]


# ---------------------------------------------------------------------------
# Day number -> calendar date candidate resolution
# ---------------------------------------------------------------------------


def test_resolve_single_certain_year() -> None:
    candidates, reasons = resolve_day_candidates(32, dt(2020, 1, 5), dt(2020, 6, 1), dt(2020, 6, 2))
    assert candidates == [dt(2020, 2, 1)]
    assert reasons == []


def test_resolve_day_366_requires_leap_year_and_stays_ambiguous() -> None:
    # UAL Day366 is the 366th day of the collection year (31 December) and only
    # exists in leap years. With no boundaries the year cannot be chosen.
    candidates, reasons = resolve_day_candidates(366, None, None, None)
    assert candidates == []
    assert REASON_YEAR_BOUNDARY_MISSING in reasons

    # A window spanning multiple leap years keeps every compatible leap year.
    candidates, reasons = resolve_day_candidates(366, dt(2015, 1, 1), dt(2021, 12, 31), dt(2022, 1, 1))
    assert dt(2016, 12, 31) in candidates
    assert dt(2020, 12, 31) in candidates
    assert all(candidate.month == 12 and candidate.day == 31 for candidate in candidates)
    assert REASON_LEAP_YEAR_AMBIGUITY in reasons
    assert REASON_MULTIPLE_CANDIDATE_YEARS in reasons
    assert REASON_CROSS_YEAR_AMBIGUITY in reasons


def test_resolve_day_366_certain_with_tight_boundaries() -> None:
    candidates, reasons = resolve_day_candidates(366, dt(2020, 12, 1), dt(2020, 12, 31), dt(2021, 1, 1))
    assert candidates == [dt(2020, 12, 31)]
    assert reasons == []


def test_resolve_cross_year_ambiguity_preserved() -> None:
    # Day 1 inside a multi-year window can belong to either calendar year.
    candidates, reasons = resolve_day_candidates(1, dt(2018, 12, 15), dt(2021, 2, 1), dt(2021, 2, 2))
    assert dt(2019, 1, 1) in candidates
    assert dt(2020, 1, 1) in candidates
    assert dt(2021, 1, 1) in candidates
    assert dt(2018, 1, 1) not in candidates  # before FirstSeen
    assert REASON_CROSS_YEAR_AMBIGUITY in reasons
    assert REASON_MULTIPLE_CANDIDATE_YEARS in reasons


def test_resolve_tight_window_resolves_year_without_cross_year_doubt() -> None:
    # FirstSeen in December makes the January day unambiguous between two years.
    candidates, reasons = resolve_day_candidates(1, dt(2019, 12, 15), dt(2020, 2, 1), dt(2020, 2, 2))
    assert candidates == [dt(2020, 1, 1)]
    assert REASON_CROSS_YEAR_AMBIGUITY not in reasons


def test_resolve_missing_boundaries_weakens_conclusion() -> None:
    candidates, reasons = resolve_day_candidates(10, None, dt(2020, 6, 1), None)
    assert dt(2020, 1, 10) in candidates
    assert REASON_YEAR_BOUNDARY_MISSING in reasons
    assert REASON_MULTIPLE_CANDIDATE_YEARS in reasons


def test_resolve_day_number_beyond_year_is_rejected() -> None:
    # Day 366 cannot exist in non-leap 2019; tight boundaries exclude every year.
    candidates, reasons = resolve_day_candidates(366, dt(2019, 1, 1), dt(2019, 12, 31), dt(2020, 1, 1))
    assert candidates == []
    assert REASON_DAY_OUT_OF_YEAR in reasons


# ---------------------------------------------------------------------------
# Overlapping snapshots: never summed
# ---------------------------------------------------------------------------


def test_overlapping_snapshots_are_not_summed() -> None:
    merger = UALMerger()
    merger.add_evidence(
        [
            make_evidence("snap-1", day_num=32, count=5, collected_at=dt(2020, 2, 10), page=1),
            make_evidence("snap-2", day_num=32, count=9, collected_at=dt(2020, 3, 10), page=2),
        ]
    )

    group = find_group(merger, dt(2020, 2, 1))
    assert group.observed_count == 9  # max, not 5 + 9
    assert group.incremental_count == 4  # 9 - 5, the genuinely new accesses
    assert group.accessed is True
    assert group.certain is True
    assert len(group.evidence) == 2


def test_overlapping_snapshots_input_order_independent() -> None:
    items = [
        make_evidence("snap-1", day_num=32, count=5, collected_at=dt(2020, 2, 10), page=1),
        make_evidence("snap-2", day_num=32, count=9, collected_at=dt(2020, 3, 10), page=2),
        make_evidence("snap-3", day_num=32, count=12, collected_at=dt(2020, 4, 10), page=3),
    ]

    reference = None
    for order in permutations(items):
        merger = UALMerger()
        merger.add_evidence(list(order))
        serialized = [(g.date, g.observed_count, g.incremental_count, g.certain) for g in merger.merge()]
        if reference is None:
            reference = serialized
        else:
            assert serialized == reference

    merger = UALMerger()
    merger.add_evidence(items)
    group = find_group(merger, dt(2020, 2, 1))
    assert group.observed_count == 12
    assert group.incremental_count == 7  # (9-5) + (12-9)


def test_duplicate_import_is_idempotent() -> None:
    merger = UALMerger()
    evidence = [make_evidence("snap-1", day_num=32, count=5, collected_at=dt(2020, 2, 10))]

    merger.add_evidence(evidence)
    merger.add_evidence(())  # empty import changes nothing
    merger.add_evidence(evidence)  # same source again
    merger.add_evidence(evidence)

    group = find_group(merger, dt(2020, 2, 1))
    assert group.observed_count == 5
    assert len(group.evidence) == 1
    assert len(merger.evidence) == 1
    assert group.incremental_count is None
    assert REASON_NO_DELTA_FIRST_OBSERVATION in group.reasons
    # A single source cannot have an ordering problem.
    assert REASON_COLLECTION_ORDER_UNKNOWN not in group.reasons


# ---------------------------------------------------------------------------
# Counter decrease: reset / year rollover, never negative
# ---------------------------------------------------------------------------


def test_counter_decrease_never_negative() -> None:
    merger = UALMerger()
    merger.add_evidence(
        [
            make_evidence("snap-1", day_num=32, count=20, collected_at=dt(2020, 2, 10), page=1),
            make_evidence("snap-2", day_num=32, count=7, collected_at=dt(2020, 3, 10), page=2),
        ]
    )

    group = find_group(merger, dt(2020, 2, 1))
    assert group.observed_count == 20
    assert group.incremental_count is None
    assert group.certain is True  # date attribution itself remains certain
    assert REASON_COUNT_DECREASE in group.reasons
    assert REASON_NEGATIVE_INCREMENT_SUPPRESSED in group.reasons


def test_mixed_increase_and_decrease_across_three_snapshots() -> None:
    merger = UALMerger()
    merger.add_evidence(
        [
            make_evidence("snap-1", day_num=32, count=5, collected_at=dt(2020, 2, 10), page=1),
            make_evidence("snap-2", day_num=32, count=9, collected_at=dt(2020, 3, 10), page=2),
            make_evidence("snap-3", day_num=32, count=3, collected_at=dt(2020, 4, 10), page=3),
        ]
    )

    group = find_group(merger, dt(2020, 2, 1))
    assert group.observed_count == 9
    # Only the 5 -> 9 segment supports an increment; the 9 -> 3 drop is suppressed.
    assert group.incremental_count == 4
    assert REASON_COUNT_DECREASE in group.reasons
    assert REASON_NEGATIVE_INCREMENT_SUPPRESSED in group.reasons


# ---------------------------------------------------------------------------
# Cross-year / missing boundary sample
# ---------------------------------------------------------------------------


def test_cross_year_missing_boundary_sample() -> None:
    merger = UALMerger()
    # LastAccess missing and collection unknown: no upper bound, year ambiguous.
    merger.add_evidence(
        [make_evidence("snap-1", day_num=1, count=4, first_seen=dt(2019, 12, 20), last_access=None, collected_at=None)]
    )

    results = [result for result in merger.merge() if result.entity_key == ENTITY]
    assert len(results) >= 2  # same evidence attributed to multiple candidate dates
    for result in results:
        assert result.observed_count == 4
        assert result.certain is False
        assert set(result.reasons) & DATE_UNCERTAINTY_REASONS
        assert result.evidence[0].day_num == 1
        assert result.evidence[0].count == 4


def test_removing_time_evidence_weakens_conclusion() -> None:
    strong = make_evidence("snap-1", day_num=32, count=5)
    assert strong.certain_date == dt(2020, 2, 1)
    assert strong.uncertain is False

    weak = make_evidence("snap-1", day_num=32, count=5, first_seen=None, last_access=None, collected_at=None)
    assert weak.certain_date is None
    assert weak.candidate_dates == ()
    assert REASON_YEAR_BOUNDARY_MISSING in weak.reasons

    merger = UALMerger()
    merger.add_evidence([weak])
    unattributed = [result for result in merger.merge() if result.date is None]
    assert len(unattributed) == 1
    assert unattributed[0].accessed is True
    assert unattributed[0].certain is False
    # Raw day number and value survive despite the lost date.
    assert unattributed[0].evidence[0].day_num == 32
    assert unattributed[0].evidence[0].count == 5


def test_missing_collection_time_blocks_cross_snapshot_increment() -> None:
    merger = UALMerger()
    merger.add_evidence(
        [
            make_evidence("snap-1", day_num=32, count=5, collected_at=None, page=1),
            make_evidence("snap-2", day_num=32, count=9, collected_at=None, page=2),
        ]
    )

    group = find_group(merger, dt(2020, 2, 1))
    assert group.observed_count == 9
    assert group.incremental_count is None
    assert REASON_COLLECTION_ORDER_UNKNOWN in group.reasons


def test_tied_collection_times_block_ordering() -> None:
    merger = UALMerger()
    merger.add_evidence(
        [
            make_evidence("snap-1", day_num=32, count=5, collected_at=dt(2020, 3, 1), page=1),
            make_evidence("snap-2", day_num=32, count=9, collected_at=dt(2020, 3, 1), page=2),
        ]
    )

    group = find_group(merger, dt(2020, 2, 1))
    assert group.incremental_count is None
    assert REASON_COLLECTION_ORDER_UNKNOWN in group.reasons


# ---------------------------------------------------------------------------
# Entity association keys keep distinct entities apart
# ---------------------------------------------------------------------------


def test_distinct_entity_keys_are_not_merged() -> None:
    other = (("RoleGuid", "role-2"), ("Address", "10.0.0.2"))
    merger = UALMerger()
    merger.add_evidence(
        [
            make_evidence("snap-1", day_num=32, count=5, entity_key=ENTITY, page=1),
            make_evidence("snap-1", day_num=32, count=8, entity_key=other, page=2),
        ]
    )

    assert find_group(merger, dt(2020, 2, 1), ENTITY).observed_count == 5
    assert find_group(merger, dt(2020, 2, 1), other).observed_count == 8


def test_full_evidence_chain_is_retained() -> None:
    merger = UALMerger()
    merger.add_evidence(
        [
            make_evidence("snap-1", day_num=32, count=5, collected_at=dt(2020, 2, 10), page=11, tag=1),
            make_evidence("snap-2", day_num=32, count=9, collected_at=dt(2020, 3, 10), page=12, tag=2),
        ]
    )

    chain = merger.evidence_for(TABLE, ENTITY, dt(2020, 2, 1))
    assert {(item.source, item.page, item.tag, item.count) for item in chain} == {
        ("snap-1", 11, 1, 5),
        ("snap-2", 12, 2, 9),
    }
    assert all(item.day_num == 32 for item in chain)


# ---------------------------------------------------------------------------
# End-to-end on the real UAL database (old interface stays intact)
# ---------------------------------------------------------------------------


def test_ual_snapshot_extracts_real_evidence(ual_db: BinaryIO) -> None:
    snapshot = Snapshot(source="current.mdb", collected_at=dt(2021, 11, 23))
    reader = UALSnapshot(ual_db)
    evidence = reader.extract_day_evidence(snapshot)

    assert evidence
    assert all(item.source == "current.mdb" for item in evidence)
    assert all(item.count > 0 for item in evidence)
    assert all(item.page is not None and item.tag is not None for item in evidence)
    assert all(item.candidate_dates for item in evidence)

    merger = UALMerger()
    merger.add_evidence(evidence)
    access_dates = merger.access_dates()
    assert access_dates == sorted(access_dates)
    assert dt(2021, 7, 23) in access_dates
    assert all(result.evidence for result in merger.merge())


def test_legacy_ual_interface_unchanged(ual_db: BinaryIO) -> None:
    from dissect.esedb.tools.ual import UAL

    db = UAL(ual_db)
    assert len(list(db.get_table_records("CLIENTS"))) == 19
    record = next(db.get_table_records("CLIENTS"))
    assert "activity_counts" in record


def test_two_snapshots_of_same_database_merge_without_summing(ual_db: BinaryIO) -> None:
    reader = UALSnapshot(ual_db)
    first = reader.extract_day_evidence(Snapshot("snap-1", dt(2021, 11, 23)))

    # Re-open the same database contents for a second snapshot.
    data_path = Path(__file__).parent / "_data" / "Current.mdb.gz"
    with gzip.open(data_path, "rb") as second_fh:
        second_reader = UALSnapshot(second_fh)
        second = second_reader.extract_day_evidence(
            Snapshot("snap-2", dt(2021, 12, 24)),
        )

    merger = UALMerger()
    merger.add_evidence(first)
    merger.add_evidence(second)

    for result in merger.merge():
        # Two copies of identical counters must never double the observed count.
        assert len({item.count for item in result.evidence}) == 1
        assert result.incremental_count == 0


def test_add_snapshot_reimport_is_idempotent(ual_db: BinaryIO) -> None:
    snapshot = Snapshot("evidence-001", dt(2021, 11, 23))
    merger = UALMerger()
    merger.add_snapshot(ual_db, snapshot)
    first_evidence = merger.evidence

    data_path = Path(__file__).parent / "_data" / "Current.mdb.gz"
    with gzip.open(data_path, "rb") as second_fh:
        merger.add_snapshot(second_fh, snapshot)
    with gzip.open(data_path, "rb") as third_fh:
        merger.add_snapshot(third_fh, snapshot)

    assert merger.evidence == first_evidence
    assert len(merger.evidence) == len(first_evidence)
