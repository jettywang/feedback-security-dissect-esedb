from __future__ import annotations

import gzip
import io
from pathlib import Path

import pytest

from dissect.esedb.c_esedb import c_esedb
from incident_response.ese_forensics import (
    COMMIT_CLEAN_HEADER,
    COMMIT_UNKNOWN,
    PARSE_DEGRADED,
    PARSE_OK,
    analyze_file,
    page_xor_checksum,
)
from incident_response.build_contradictions import build_all

DATA = Path(__file__).parent / "_data"


@pytest.fixture(scope="module")
def manifest(tmp_path_factory: pytest.TempPathFactory) -> dict:
    # Build every contradiction copy in an isolated directory so the test
    # never touches the repository fixtures or the committed samples.
    import incident_response.build_contradictions as builder

    original_samples = builder.SAMPLES
    work = tmp_path_factory.mktemp("forensic_samples")
    builder.SAMPLES = str(work)
    try:
        result = builder.build_all()
    finally:
        builder.SAMPLES = original_samples
    return result


def _sample_path(manifest: dict, name: str) -> str:
    for scenario in manifest["scenarios"]:
        if scenario["sample"] == name:
            return scenario["path"]
    raise KeyError(name)


def _codes(report: dict) -> set[str]:
    return {finding["code"] for finding in report["findings"]}


def test_pristine_baseline(manifest: dict) -> None:
    report = analyze_file(_sample_path(manifest, "basic.pristine.edb"))
    assert report["structural_parse_state"] == PARSE_OK
    assert report["transaction_commit_state"] == COMMIT_CLEAN_HEADER
    assert report["header"]["header_checksum_ok"] is True
    assert report["header"]["shadow_mismatches"] == []
    assert report["pages"]["bad_reproducible_checksum"] == 0
    # No data-page orphans in a healthy database.
    assert report["btree"]["coverage"]["orphan_pages"] == []
    assert {"HDR_CLEAN", "SHADOW_MATCH"} <= _codes(report)


def test_dirty_shutdown_header_contradiction(manifest: dict) -> None:
    report = analyze_file(_sample_path(manifest, "dirty-shutdown.edb"))
    codes = _codes(report)
    assert {"HDR_DIRTY", "SHADOW_DIVERGENCE", "HDR_NO_CONSISTENT_LGPOS"} <= codes
    assert report["transaction_commit_state"] == COMMIT_UNKNOWN
    divergence = next(f for f in report["findings"] if f["code"] == "SHADOW_DIVERGENCE")
    fields = {item["field"] for item in divergence["detail"]["mismatches"]}
    assert {"dbstate", "dbtimeDirtied"} <= fields
    # Pages themselves remain parseable even though commit state is unknown.
    assert report["structural_parse_state"] == PARSE_OK


def test_mixed_time_page_detection(manifest: dict) -> None:
    report = analyze_file(_sample_path(manifest, "mixed-time-page.edb"))
    assert "PAGE_TIME_FUTURE" in _codes(report)
    page_time = report["page_time"]
    assert 14 in page_time["pages_newer_than_header"]
    assert page_time["max_page_dbtime"] > page_time["header_dbtimeDirtied"]
    assert report["transaction_commit_state"] == COMMIT_UNKNOWN


def test_missing_catalog_target(manifest: dict) -> None:
    report = analyze_file(_sample_path(manifest, "missing-catalog-target.edb"))
    codes = _codes(report)
    assert "CATALOG_DANGLING_ROOT" in codes
    dangling = next(f for f in report["findings"] if f["code"] == "CATALOG_DANGLING_ROOT")
    assert dangling["detail"]["roots"] == [31]
    # The table row still parses, but yields no records; commit state unknown.
    basic = next(row for row in report["btree"]["records"] if row["table"] == "basic")
    assert basic["records_decoded"] == 0


def test_broken_btree_link(manifest: dict) -> None:
    report = analyze_file(_sample_path(manifest, "broken-btree-link.edb"))
    codes = _codes(report)
    assert {"BTREE_LINK_OOB", "BTREE_LINK"} <= codes
    assert report["structural_parse_state"] == PARSE_DEGRADED
    link = next(f for f in report["findings"] if f["code"] == "BTREE_LINK_OOB")
    assert link["detail"]["links"][0]["target"] == 999


def test_tampered_page_checksum_failure(manifest: dict) -> None:
    report = analyze_file(_sample_path(manifest, "tampered-page.edb"))
    assert "PAGE_CHECKSUM" in _codes(report)
    assert report["pages"]["bad_reproducible_checksum"] == 1
    bad = next(f for f in report["findings"] if f["code"] == "PAGE_CHECKSUM")
    assert bad["detail"]["logical_pgno"] == 14
    # Header still claims clean, demonstrating that the flag alone is not proof;
    # the checksum contradiction forces commit state back to indeterminate.
    assert report["header"]["dbstate"] == 3
    assert report["transaction_commit_state"] == COMMIT_UNKNOWN


def test_xor_checksum_formula_matches_all_fixture_pages() -> None:
    raw = gzip.open(DATA / "basic.edb.gz", "rb").read()
    page_size = c_esedb.DBFILEHDR(io.BytesIO(raw)).cbPageSize or 4096
    count = 0
    for logical in range(1, len(raw) // page_size - 1):
        buf = raw[(logical + 1) * page_size : (logical + 2) * page_size]
        if all(b == 0 for b in buf):
            continue
        stored_ecc, _stored_xor = c_esedb.uint32(buf[:4]), c_esedb.uint32(buf[4:8])
        assert page_xor_checksum(buf, logical) == stored_ecc
        count += 1
    assert count > 0


def test_long_value_pages_are_not_orphans(tmp_path: Path) -> None:
    raw = gzip.open(DATA / "multi.edb.gz", "rb").read()
    sample = tmp_path / "multi.edb"
    sample.write_bytes(raw)
    report = analyze_file(str(sample))
    # LongValue B-tree pages (e.g. 43-47) must be covered via the catalog
    # LongValue row rather than reported as orphans.
    assert report["btree"]["coverage"]["orphan_pages"] == []
    assert {43, 44, 45, 46, 47} <= set(report["btree"]["coverage"]["long_value_pages"])
    assert report["pages"]["bad_reproducible_checksum"] == 0


def test_large_page_checksums_are_engine_validated_only(tmp_path: Path) -> None:
    raw = gzip.open(DATA / "large.edb.gz", "rb").read()
    sample = tmp_path / "large.edb"
    sample.write_bytes(raw)
    report = analyze_file(str(sample))
    # A healthy large-page database must not produce false corruption findings.
    assert report["pages"]["bad_reproducible_checksum"] == 0
    assert report["pages"]["large_page_first_block_only_checksums"] > 0
    assert "LARGE_PAGE_CHECKSUM_SCOPE" in _codes(report)


def test_analyzer_never_writes(tmp_path: Path, manifest: dict) -> None:
    sample = Path(_sample_path(manifest, "dirty-shutdown.edb"))
    before = sample.read_bytes()
    analyze_file(str(sample))
    assert sample.read_bytes() == before
    assert report_is_read_only(analyze_file(str(sample)))


def report_is_read_only(report: dict) -> bool:
    return report["mode"] == "read-only" and report["mutations_performed"] == [] and not report["replay_attempted"]
