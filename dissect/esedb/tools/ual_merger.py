from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.ts import wintimestamp

from dissect.esedb.tools.ual import UAL, convert_day_num_to_date

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from dissect.esedb.c_esedb import RecordValue

# Conservative bound on how far away from the available boundaries we are still
# willing to consider a calendar year as a possible owner of a DayNNN counter.
MAX_YEAR_SEARCH = 5

DAY_COLUMN_PREFIX = "Day"

# Uncertainty reasons. These are machine readable codes; they explain *why* a
# conclusion cannot be made stronger, they never silently resolve ambiguity.
REASON_YEAR_BOUNDARY_MISSING = "year_boundary_missing"
REASON_MULTIPLE_CANDIDATE_YEARS = "multiple_candidate_years"
REASON_CROSS_YEAR_AMBIGUITY = "cross_year_ambiguity"
REASON_LEAP_YEAR_AMBIGUITY = "leap_year_ambiguity"
REASON_DAY_OUT_OF_YEAR = "day_out_of_year"
REASON_COLLECTION_ORDER_UNKNOWN = "collection_order_unknown"
REASON_COUNT_DECREASE = "count_decrease_possible_reset_or_year_rollover"
REASON_NEGATIVE_INCREMENT_SUPPRESSED = "negative_increment_suppressed"
REASON_NO_DELTA_FIRST_OBSERVATION = "no_delta_first_observation"

# Reasons that weaken the attribution of a day number to a calendar date.
DATE_UNCERTAINTY_REASONS = frozenset(
    {
        REASON_YEAR_BOUNDARY_MISSING,
        REASON_MULTIPLE_CANDIDATE_YEARS,
        REASON_CROSS_YEAR_AMBIGUITY,
        REASON_LEAP_YEAR_AMBIGUITY,
        REASON_DAY_OUT_OF_YEAR,
    }
)

DEFAULT_ENTITY_KEY_FIELDS = ("RoleGuid", "TenantId", "Address", "AuthenticatedUserName", "ClientName")
DATETIME_BOUNDARY_FIELDS = ("FirstSeen", "InsertDate", "LastAccess", "LastSeen", "CreationTime")


@dataclass(frozen=True)
class Snapshot:
    """A UAL database snapshot as offered by the caller.

    Args:
        source: Caller supplied identifier of where the database came from
            (e.g. a file path or evidence number). Used for grouping and for
            idempotent re-imports.
        collected_at: When the database was collected/acquired, if known.
    """

    source: str
    collected_at: datetime.datetime | None = None


@dataclass(frozen=True)
class DayEvidence:
    """A single non-zero ``DayNNN`` counter observed in one snapshot record.

    The original day number, raw counter value and the exact source page/tag
    location are always retained, even when the calendar date cannot be
    resolved unambiguously.
    """

    source: str
    table: str
    page: int | None
    tag: int | None
    entity_key: tuple[tuple[str, str | None], ...]
    day_num: int
    count: int
    first_seen: datetime.datetime | None
    last_access: datetime.datetime | None
    collected_at: datetime.datetime | None
    candidate_dates: tuple[datetime.datetime, ...]
    reasons: tuple[str, ...]

    @property
    def certain_date(self) -> datetime.datetime | None:
        """The single calendar date this evidence belongs to, if unambiguous."""
        return self.candidate_dates[0] if len(self.candidate_dates) == 1 else None

    @property
    def uncertain(self) -> bool:
        return bool(self.reasons) or self.certain_date is None


@dataclass(frozen=True)
class MergedDayAccess:
    """Conservative, merged conclusion for one entity on one calendar date.

    ``observed_count`` is the strongest count we are willing to report. Overlapping
    snapshots are never added together; it is the largest count seen in any single
    snapshot (the counters are cumulative within a UAL collection year).

    ``incremental_count`` is the number of *new* accesses attributable to this date
    between two chronologically ordered snapshots. It is only computed when the
    entity key, date attribution and snapshot ordering are all certain. A counter
    decrease never produces a negative increment.
    """

    table: str
    entity_key: tuple[tuple[str, str | None], ...]
    date: datetime.datetime | None
    observed_count: int
    incremental_count: int | None
    certain: bool
    reasons: tuple[str, ...]
    evidence: tuple[DayEvidence, ...]

    @property
    def accessed(self) -> bool:
        """Whether access on this date is supported by at least one counter."""
        return self.observed_count > 0


class UALSnapshot(UAL):
    """Single-snapshot UAL reader that additionally yields structured day evidence."""

    def extract_day_evidence(
        self,
        snapshot: Snapshot,
        entity_key_fields: Sequence[str] = DEFAULT_ENTITY_KEY_FIELDS,
    ) -> list[DayEvidence]:
        """Extract every non-zero ``DayNNN`` counter as :class:`DayEvidence`."""
        evidence: list[DayEvidence] = []
        for table in self.get_tables():
            if table.name.startswith("MSys"):
                continue
            evidence.extend(self._extract_table_evidence(table.name, snapshot, tuple(entity_key_fields)))
        return evidence

    def _extract_table_evidence(
        self, table_name: str, snapshot: Snapshot, entity_key_fields: tuple[str, ...]
    ) -> Iterator[DayEvidence]:
        try:
            table = self.esedb.table(table_name)
        except KeyError:
            return

        column_names = {column.name for column in table.columns}
        key_fields = tuple(name for name in entity_key_fields if name in column_names)

        for record in table.records():
            boundaries = _read_boundaries(record)
            first_seen = boundaries.get("FirstSeen") or boundaries.get("InsertDate") or boundaries.get("CreationTime")
            last_access = boundaries.get("LastAccess") or boundaries.get("LastSeen")
            page = getattr(getattr(getattr(record, "_node", None), "tag", None), "page", None)
            page_num = getattr(page, "num", None)
            tag_num = getattr(getattr(getattr(record, "_node", None), "tag", None), "num", None)

            entity_key = _build_entity_key(record, key_fields)
            day_values = _read_day_values(record, table)
            if not day_values:
                continue

            for day_num, count in day_values:
                if not count:
                    # Zero/missing counters are not evidence of activity; keep
                    # nothing rather than emit records that cannot support a date.
                    continue
                candidate_dates, reasons = resolve_day_candidates(
                    day_num,
                    first_seen,
                    last_access,
                    snapshot.collected_at,
                    extra_lower=boundaries.get("InsertDate"),
                    extra_upper=boundaries.get("LastSeen"),
                )
                yield DayEvidence(
                    source=snapshot.source,
                    table=table_name,
                    page=page_num,
                    tag=tag_num,
                    entity_key=entity_key,
                    day_num=day_num,
                    count=int(count),
                    first_seen=first_seen,
                    last_access=last_access,
                    collected_at=snapshot.collected_at,
                    candidate_dates=tuple(candidate_dates),
                    reasons=tuple(reasons),
                )


class UALMerger:
    """Merge :class:`DayEvidence` from several snapshots of the same server.

    The merger is deliberately conservative:

    * evidence is grouped by the caller supplied snapshot source and the entity
      association key, so overlapping snapshots are never summed;
    * date candidates are carried with their uncertainty reasons instead of being
      forced onto one calendar date;
    * cross-snapshot increments are only computed when the entity key, date and
      collection order are all certain;
    * counter decreases (reset or UAL year rollover) never produce negative counts
      and the reset time is never guessed;
    * re-importing the same source is idempotent.
    """

    def __init__(self) -> None:
        self._evidence: dict[tuple, DayEvidence] = {}

    def add_snapshot(
        self,
        fh: BinaryIO,
        snapshot: Snapshot,
        entity_key_fields: Sequence[str] = DEFAULT_ENTITY_KEY_FIELDS,
    ) -> list[DayEvidence]:
        """Read one UAL database and merge its evidence.

        Re-adding the same source replaces the previous evidence of that source,
        making repeated imports idempotent.
        """
        reader = UALSnapshot(fh)
        return self.add_evidence(reader.extract_day_evidence(snapshot, entity_key_fields))

    def add_evidence(self, evidence: Sequence[DayEvidence]) -> list[DayEvidence]:
        """Merge pre-extracted evidence.

        Evidence already present for the same source is replaced first, so calling
        this twice with the same data yields the same merged state.
        """
        incoming_sources = {item.source for item in evidence}
        if incoming_sources:
            self._evidence = {
                identity: item for identity, item in self._evidence.items() if item.source not in incoming_sources
            }

        added: list[DayEvidence] = []
        for item in evidence:
            identity = (item.source, item.table, item.page, item.tag, item.day_num)
            existing = self._evidence.get(identity)
            if existing is not None and existing == item:
                # Exact duplicate import: keep one copy, still report it once.
                added.append(item)
                continue
            self._evidence[identity] = item
            added.append(item)
        return added

    @property
    def evidence(self) -> tuple[DayEvidence, ...]:
        """All retained raw evidence, in a stable order."""
        return tuple(self._evidence[key] for key in sorted(self._evidence))

    def merge(self) -> list[MergedDayAccess]:
        """Produce the conservative per-entity, per-date conclusions."""
        grouped: dict[tuple[str, tuple[tuple[str, str | None], ...], datetime.datetime | None], list[DayEvidence]] = {}
        unattributed: list[DayEvidence] = []

        for item in self.evidence:
            for date in item.candidate_dates:
                grouped.setdefault((item.table, item.entity_key, date), []).append(item)
            if not item.candidate_dates:
                unattributed.append(item)

        results: list[MergedDayAccess] = []
        for (table, entity_key, date), items in grouped.items():
            results.append(self._merge_group(table, entity_key, date, items))
        results.extend(
            MergedDayAccess(
                table=item.table,
                entity_key=item.entity_key,
                date=None,
                observed_count=item.count,
                incremental_count=None,
                certain=False,
                reasons=tuple(sorted({*item.reasons, REASON_YEAR_BOUNDARY_MISSING})),
                evidence=(item,),
            )
            for item in unattributed
        )

        results.sort(key=_merged_sort_key)
        return results

    def access_dates(self) -> list[datetime.datetime]:
        """Distinct calendar dates for which access evidence exists, sorted."""
        dates = {result.date for result in self.merge() if result.accessed and result.date is not None}
        return sorted(dates)

    def evidence_for(
        self, table: str, entity_key: tuple[tuple[str, str | None], ...], date: datetime.datetime
    ) -> tuple[DayEvidence, ...]:
        """Return the full evidence chain for one entity/date combination."""
        return tuple(
            item
            for item in self.evidence
            if item.table == table and item.entity_key == entity_key and date in item.candidate_dates
        )

    def _merge_group(
        self,
        table: str,
        entity_key: tuple[tuple[str, str | None], ...],
        date: datetime.datetime | None,
        items: list[DayEvidence],
    ) -> MergedDayAccess:
        reasons = set()
        for item in items:
            reasons.update(item.reasons)

        # Per source we may in theory hold several records (different pages/tags)
        # for the same day. Collapse to the strongest observation per source.
        per_source: dict[str, DayEvidence] = {}
        for item in items:
            current = per_source.get(item.source)
            if current is None or item.count > current.count:
                per_source[item.source] = item

        ordered = _order_by_collection(per_source.values())
        order_uncertain = ordered is None
        if order_uncertain and len(per_source) >= 2:
            # Ordering only matters when evidence from several sources must be sequenced.
            reasons.add(REASON_COLLECTION_ORDER_UNKNOWN)
        ordered = sorted(per_source.values(), key=lambda item: (item.source,)) if order_uncertain else ordered

        observed_count = max(item.count for item in per_source.values())

        incremental_count = None
        if len(per_source) >= 2 and not order_uncertain and all(item.certain_date is not None for item in ordered):
            incremental_count, increment_reasons = _conservative_increment(ordered)
            reasons.update(increment_reasons)
        elif len(per_source) == 1:
            reasons.add(REASON_NO_DELTA_FIRST_OBSERVATION)
        elif order_uncertain:
            reasons.add(REASON_COLLECTION_ORDER_UNKNOWN)

        certain = not (reasons & DATE_UNCERTAINTY_REASONS) and all(not item.uncertain for item in items)
        return MergedDayAccess(
            table=table,
            entity_key=entity_key,
            date=date,
            observed_count=observed_count,
            incremental_count=incremental_count,
            certain=certain,
            reasons=tuple(sorted(reasons)),
            evidence=tuple(
                sorted(
                    items,
                    key=lambda item: (
                        item.source,
                        item.page if item.page is not None else -1,
                        item.tag if item.tag is not None else -1,
                        item.day_num,
                    ),
                )
            ),
        )


def resolve_day_candidates(
    day_num: int,
    first_seen: datetime.datetime | None,
    last_access: datetime.datetime | None,
    collected_at: datetime.datetime | None,
    extra_lower: datetime.datetime | None = None,
    extra_upper: datetime.datetime | None = None,
) -> tuple[list[datetime.datetime], list[str]]:
    """Resolve a ``DayNNN`` number into possible calendar dates.

    Ambiguity is preserved: every calendar year compatible with the available
    boundaries is returned, together with machine readable reasons explaining why
    the result is not stronger.

    ``first_seen``/``last_access`` are the record's primary boundaries;
    ``extra_lower``/``extra_upper`` (e.g. ``InsertDate``/``LastSeen``) further
    constrain the window without replacing them.
    """
    reasons: list[str] = []
    lower_boundaries = [ts for ts in (first_seen, extra_lower) if ts is not None]
    upper_boundaries = [ts for ts in (last_access, collected_at, extra_upper) if ts is not None]
    if not lower_boundaries and not upper_boundaries:
        return [], [REASON_YEAR_BOUNDARY_MISSING]

    lower_bound = min(lower_boundaries, default=None)
    upper_bound = max(upper_boundaries, default=None)
    if lower_bound is not None and upper_bound is not None and lower_bound > upper_bound:
        # Contradictory boundaries (clock skew, partial data): widen the search
        # window and let the per-boundary checks below filter conservatively.
        lower_bound, upper_bound = upper_bound, lower_bound

    search_min = (lower_bound or upper_bound).year
    search_max = (upper_bound or lower_bound).year
    candidate_years = list(range(search_min - MAX_YEAR_SEARCH, search_max + MAX_YEAR_SEARCH + 1))
    valid_years: list[int] = []
    for year in candidate_years:
        if day_num > _days_in_year(year):
            continue
        candidate = convert_day_num_to_date(year, day_num)
        if any(candidate.date() < ts.date() for ts in lower_boundaries):
            continue
        if any(candidate.date() > ts.date() for ts in upper_boundaries):
            continue
        valid_years.append(year)

    if not valid_years:
        reasons.append(REASON_DAY_OUT_OF_YEAR)
        return [], reasons

    if len(valid_years) > 1:
        reasons.append(REASON_MULTIPLE_CANDIDATE_YEARS)
        reasons.append(REASON_CROSS_YEAR_AMBIGUITY)
        # Day 366 only exists in leap years: with several candidates the leap-year
        # nature of the column cannot be attributed to one collection year.
        if day_num == 366:
            reasons.append(REASON_LEAP_YEAR_AMBIGUITY)

    if first_seen is None or last_access is None or collected_at is None:
        reasons.append(REASON_YEAR_BOUNDARY_MISSING)

    return [convert_day_num_to_date(year, day_num) for year in valid_years], reasons


def _conservative_increment(
    ordered: list[DayEvidence],
) -> tuple[int | None, set[str]]:
    reasons: set[str] = set()
    increments: list[int] = []
    for earlier, later in zip(ordered, ordered[1:]):
        if later.count >= earlier.count:
            increments.append(later.count - earlier.count)
        else:
            # A decrease indicates a counter reset or UAL year rollover. We must
            # not report negative access and must not guess when the reset happened.
            reasons.add(REASON_COUNT_DECREASE)
            reasons.add(REASON_NEGATIVE_INCREMENT_SUPPRESSED)

    if not increments:
        return None, reasons
    return sum(increments), reasons


def _order_by_collection(items: Sequence[DayEvidence]) -> list[DayEvidence] | None:
    timestamps = [item.collected_at for item in items]
    if any(ts is None for ts in timestamps):
        return None
    ordered = sorted(items, key=lambda item: (item.collected_at, item.source))
    stamps = [item.collected_at for item in ordered]
    if len(set(stamps)) != len(stamps):
        # Ties cannot be ordered chronologically.
        return None
    return ordered


def _days_in_year(year: int) -> int:
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    return 366 if leap else 365


def _read_day_values(record: object, table: object) -> list[tuple[int, RecordValue]]:
    values = []
    for column in table.columns:
        if column.name.startswith(DAY_COLUMN_PREFIX):
            suffix = column.name[len(DAY_COLUMN_PREFIX) :]
            if not suffix.isdigit():
                continue
            values.append((int(suffix), record.get(column.name)))
    values.sort()
    return values


def _read_timestamp(record: object, name: str) -> datetime.datetime | None:
    try:
        raw = record.get(name)
    except KeyError:
        return None
    if raw is None:
        return None
    return wintimestamp(raw)


def _read_boundaries(record: object) -> dict[str, datetime.datetime]:
    return {
        name: timestamp for name in DATETIME_BOUNDARY_FIELDS if (timestamp := _read_timestamp(record, name)) is not None
    }


def _build_entity_key(record: object, key_fields: tuple[str, ...]) -> tuple[tuple[str, str | None], ...]:
    key = []
    for name in key_fields:
        value = record.get(name)
        if name == "Address" and isinstance(value, bytes):
            value = str(ipaddress.ip_address(value))
        key.append((name, None if value is None else str(value)))
    return tuple(key)


def _merged_sort_key(result: MergedDayAccess) -> tuple:
    date_key = result.date or datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
    return (result.table, result.entity_key, date_key)
