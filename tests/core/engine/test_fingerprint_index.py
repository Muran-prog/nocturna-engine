"""Comprehensive edge-case tests for FindingFingerprintIndex."""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from nocturna_engine.exceptions import FingerprintIndexCorruptionError
from nocturna_engine.core.engine.fingerprint_index import (
    FindingFingerprintIndex,
    FingerprintTrendEntry,
    _normalize_observed_at,
    _parse_iso_datetime,
)
from nocturna_engine.models.finding import Finding, SeverityLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(*, title: str = "Test finding", target: str = "example.com", **kwargs: Any) -> Finding:
    defaults: dict[str, Any] = {
        "description": "Test finding description.",
        "severity": SeverityLevel.LOW,
        "tool": "test_tool",
    }
    defaults.update(kwargs)
    return Finding(title=title, target=target, **defaults)


# ---------------------------------------------------------------------------
# _normalize_observed_at tests
# ---------------------------------------------------------------------------


class TestNormalizeObservedAt:
    def test_none_returns_utc_now(self):
        before = datetime.now(UTC)
        result = _normalize_observed_at(None)
        after = datetime.now(UTC)
        assert before <= result <= after
        assert result.tzinfo is not None

    def test_naive_datetime_gets_utc(self):
        naive = datetime(2025, 1, 15, 12, 0, 0)
        result = _normalize_observed_at(naive)
        assert result.tzinfo is UTC
        assert result.year == 2025

    def test_aware_datetime_converted_to_utc(self):
        eastern = timezone(timedelta(hours=-5))
        aware = datetime(2025, 6, 15, 12, 0, 0, tzinfo=eastern)
        result = _normalize_observed_at(aware)
        assert result.tzinfo is not None
        assert result.hour == 17  # 12 + 5


# ---------------------------------------------------------------------------
# _parse_iso_datetime tests
# ---------------------------------------------------------------------------


class TestParseIsoDatetime:
    def test_valid_iso_string(self):
        result = _parse_iso_datetime("2025-01-15T12:00:00+00:00")
        assert result is not None
        assert result.year == 2025

    def test_naive_iso_string_gets_utc(self):
        result = _parse_iso_datetime("2025-01-15T12:00:00")
        assert result is not None
        assert result.tzinfo is UTC

    def test_non_string_returns_none(self):
        assert _parse_iso_datetime(123) is None
        assert _parse_iso_datetime(None) is None
        assert _parse_iso_datetime([]) is None

    def test_invalid_string_returns_none(self):
        assert _parse_iso_datetime("not-a-date") is None
        assert _parse_iso_datetime("") is None


# ---------------------------------------------------------------------------
# FingerprintTrendEntry tests
# ---------------------------------------------------------------------------


class TestFingerprintTrendEntry:
    def test_to_dict(self):
        now = datetime.now(UTC)
        entry = FingerprintTrendEntry(
            fingerprint="abc123",
            first_seen=now,
            last_seen=now,
            count=5,
        )
        d = entry.to_dict()
        assert d["fingerprint"] == "abc123"
        assert d["count"] == 5
        assert "first_seen" in d
        assert "last_seen" in d


# ---------------------------------------------------------------------------
# FindingFingerprintIndex — core operations
# ---------------------------------------------------------------------------


class TestFindingFingerprintIndexBasic:
    def test_empty_index(self):
        index = FindingFingerprintIndex()
        assert len(index) == 0
        assert index.snapshot() == {}
        assert index.get("nonexistent") is None

    def test_observe_fingerprints_adds_entries(self):
        index = FindingFingerprintIndex()
        result = index.observe_fingerprints({"fp1", "fp2"})
        assert len(index) == 2
        assert "fp1" in result
        assert "fp2" in result
        assert result["fp1"].count == 1
        assert result["fp2"].count == 1

    def test_observe_same_fingerprint_increments_count(self):
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["fp1"])
        index.observe_fingerprints(["fp1"])
        index.observe_fingerprints(["fp1"])
        entry = index.get("fp1")
        assert entry is not None
        assert entry.count == 3

    def test_observe_fingerprints_updates_last_seen(self):
        index = FindingFingerprintIndex()
        t1 = datetime(2025, 1, 1, tzinfo=UTC)
        t2 = datetime(2025, 6, 1, tzinfo=UTC)
        index.observe_fingerprints(["fp1"], observed_at=t1)
        index.observe_fingerprints(["fp1"], observed_at=t2)
        entry = index.get("fp1")
        assert entry is not None
        assert entry.first_seen == t1
        assert entry.last_seen == t2
        assert entry.count == 2

    def test_observe_fingerprints_strips_whitespace(self):
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["  fp1  ", "fp2 "])
        assert index.get("fp1") is not None
        assert index.get("fp2") is not None

    def test_observe_fingerprints_ignores_empty_strings(self):
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["", "  ", "valid"])
        assert len(index) == 1
        assert index.get("valid") is not None

    def test_observe_findings_uses_finding_fingerprint(self):
        index = FindingFingerprintIndex()
        f1 = _make_finding(title="Finding one")
        f2 = _make_finding(title="Finding two")
        result = index.observe_findings([f1, f2])
        assert f1.fingerprint in result
        assert f2.fingerprint in result
        assert len(index) == 2

    def test_observe_findings_empty_list(self):
        index = FindingFingerprintIndex()
        result = index.observe_findings([])
        assert result == {}
        assert len(index) == 0

    def test_identical_fingerprints_count_once_per_observe(self):
        """Two findings with same fingerprint observed in single call count as 1."""
        index = FindingFingerprintIndex()
        f1 = _make_finding(title="Same title", cwe="CWE-79", evidence={"k": "v"})
        f2 = _make_finding(title="Same title", cwe="CWE-79", evidence={"k": "v"})
        assert f1.fingerprint == f2.fingerprint
        result = index.observe_findings([f1, f2])
        # Fingerprints are deduplicated before counting
        entry = result[f1.fingerprint]
        assert entry.count == 1

    def test_different_fingerprints_tracked_separately(self):
        index = FindingFingerprintIndex()
        f1 = _make_finding(title="Alpha finding")
        f2 = _make_finding(title="Beta finding")
        assert f1.fingerprint != f2.fingerprint
        index.observe_findings([f1, f2])
        assert len(index) == 2

    def test_snapshot_returns_sorted_dict(self):
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["zzz", "aaa", "mmm"])
        snap = index.snapshot()
        keys = list(snap.keys())
        assert keys == sorted(keys)

    def test_get_returns_none_for_missing(self):
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["exists"])
        assert index.get("nonexistent") is None

    def test_len_reflects_unique_fingerprints(self):
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["a", "b", "c"])
        assert len(index) == 3
        index.observe_fingerprints(["a"])
        assert len(index) == 3  # still 3, no new fingerprint


# ---------------------------------------------------------------------------
# Persistence tests (file-backed storage)
# ---------------------------------------------------------------------------


class TestFindingFingerprintIndexPersistence:
    def _make_tmp_dir(self) -> Path:
        return Path(tempfile.mkdtemp(prefix="fp_idx_test_"))

    def test_persist_and_load_roundtrip(self):
        td = self._make_tmp_dir()
        try:
            storage = td / "index.json"
            index = FindingFingerprintIndex(storage_path=storage)
            t = datetime(2025, 3, 1, 10, 0, 0, tzinfo=UTC)
            index.observe_fingerprints(["fp_a", "fp_b"], observed_at=t)

            # New index loading same file
            index2 = FindingFingerprintIndex(storage_path=storage)
            assert len(index2) == 2
            entry = index2.get("fp_a")
            assert entry is not None
            assert entry.count == 1
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_persist_creates_parent_dirs(self):
        td = self._make_tmp_dir()
        try:
            storage = td / "nested" / "deep" / "index.json"
            index = FindingFingerprintIndex(storage_path=storage)
            index.observe_fingerprints(["fp1"])
            assert storage.exists()
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_load_nonexistent_file_is_noop(self):
        td = self._make_tmp_dir()
        try:
            storage = td / "missing.json"
            index = FindingFingerprintIndex(storage_path=storage)
            assert len(index) == 0
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_load_corrupted_json_resets(self):
        td = self._make_tmp_dir()
        try:
            storage = td / "broken.json"
            storage.write_text("{invalid json", encoding="utf-8")
            # Should raise FingerprintIndexCorruptionError wrapping json.JSONDecodeError
            with pytest.raises(FingerprintIndexCorruptionError) as exc_info:
                FindingFingerprintIndex(storage_path=storage)
            assert exc_info.value.__cause__ is not None
            assert isinstance(exc_info.value.__cause__, json.JSONDecodeError)
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_load_entries_not_dict_ignored(self):
        td = self._make_tmp_dir()
        try:
            storage = td / "bad_entries.json"
            storage.write_text(json.dumps({"entries": "not-a-dict"}), encoding="utf-8")
            index = FindingFingerprintIndex(storage_path=storage)
            assert len(index) == 0
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_load_skips_invalid_entries(self):
        td = self._make_tmp_dir()
        try:
            storage = td / "partial.json"
            payload = {
                "entries": {
                    "valid_fp": {
                        "fingerprint": "valid_fp",
                        "first_seen": "2025-01-01T00:00:00+00:00",
                        "last_seen": "2025-01-02T00:00:00+00:00",
                        "count": 3,
                    },
                    "": {  # empty key - skipped
                        "first_seen": "2025-01-01T00:00:00+00:00",
                        "last_seen": "2025-01-02T00:00:00+00:00",
                        "count": 1,
                    },
                    "bad_count": {
                        "first_seen": "2025-01-01T00:00:00+00:00",
                        "last_seen": "2025-01-02T00:00:00+00:00",
                        "count": -1,  # negative - skipped
                    },
                    "no_dates": {
                        "count": 1,  # missing dates - skipped
                    },
                    "not_dict_entry": "just_a_string",  # skipped
                }
            }
            storage.write_text(json.dumps(payload), encoding="utf-8")
            index = FindingFingerprintIndex(storage_path=storage)
            assert len(index) == 1
            assert index.get("valid_fp") is not None
            assert index.get("valid_fp").count == 3
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_configure_storage_none_clears_path(self):
        index = FindingFingerprintIndex()
        index.configure_storage(None)
        assert index._storage_path is None

    def test_persist_without_storage_is_noop(self):
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["fp1"])
        # Should not raise
        index.persist()

    def test_atomic_write_via_tmp_file(self):
        """Persist uses atomic tmp-then-rename pattern."""
        td = Path(tempfile.mkdtemp(prefix="fp_idx_test_"))
        try:
            storage = td / "atomic.json"
            index = FindingFingerprintIndex(storage_path=storage)
            index.observe_fingerprints(["fp1"])
            # After persist, the .tmp file should not remain
            tmp_file = storage.with_suffix(f"{storage.suffix}.tmp")
            assert not tmp_file.exists()
            assert storage.exists()
        finally:
            shutil.rmtree(td, ignore_errors=True)

# ---------------------------------------------------------------------------
# Cross-run trend tracking scenario
# ---------------------------------------------------------------------------


class TestTrendTracking:
    def test_trend_across_multiple_runs(self):
        """Simulate multiple scan runs and verify trend counters."""
        td = Path(tempfile.mkdtemp(prefix="fp_idx_trend_"))
        try:
            storage = td / "trends.json"

            # Run 1
            idx1 = FindingFingerprintIndex(storage_path=storage)
            t1 = datetime(2025, 1, 1, tzinfo=UTC)
            idx1.observe_fingerprints(["fp_a", "fp_b"], observed_at=t1)

            # Run 2 (new index instance, same storage)
            idx2 = FindingFingerprintIndex(storage_path=storage)
            t2 = datetime(2025, 2, 1, tzinfo=UTC)
            idx2.observe_fingerprints(["fp_a", "fp_c"], observed_at=t2)

            assert idx2.get("fp_a").count == 2
            assert idx2.get("fp_a").first_seen == t1
            assert idx2.get("fp_a").last_seen == t2
            assert idx2.get("fp_b").count == 1
            assert idx2.get("fp_c").count == 1
        finally:
            shutil.rmtree(td, ignore_errors=True)
    def test_trend_new_finding_vs_recurring(self):
        """New findings start at count=1, recurring increment."""
        index = FindingFingerprintIndex()
        index.observe_fingerprints(["recurring"])
        index.observe_fingerprints(["recurring"])
        index.observe_fingerprints(["new_one", "recurring"])

        assert index.get("recurring").count == 3
        assert index.get("new_one").count == 1


# ---------------------------------------------------------------------------
# Parametrized edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fingerprints",
    [
        set(),       # empty set
        [],          # empty list
        (),          # empty tuple
        ["", " "],   # all blank
    ],
    ids=["empty-set", "empty-list", "empty-tuple", "all-blank"],
)
def test_observe_fingerprints_empty_inputs(fingerprints: set[str] | list[str] | tuple[str, ...]):
    """Empty or blank-only inputs don't add entries."""
    index = FindingFingerprintIndex()
    result = index.observe_fingerprints(fingerprints)
    assert len(index) == 0
    assert result == {}


@pytest.mark.parametrize(
    "input_type",
    [set, list, tuple],
    ids=["set", "list", "tuple"],
)
def test_observe_fingerprints_accepts_all_collection_types(input_type: type):
    """observe_fingerprints works with set, list, and tuple."""
    index = FindingFingerprintIndex()
    collection = input_type(["fp1", "fp2"])
    result = index.observe_fingerprints(collection)
    assert len(index) == 2
    assert "fp1" in result
    assert "fp2" in result



# ---------------------------------------------------------------------------
# _atomic_replace / persist smoke test (SEC-11)
# ---------------------------------------------------------------------------


class TestAtomicReplacePersist:
    """Verify persist() with _atomic_replace works on the normal path."""

    def test_persist_succeeds_with_atomic_replace(self):
        td = Path(tempfile.mkdtemp(prefix="fp_idx_atomic_"))
        try:
            storage = td / "atomic_index.json"
            index = FindingFingerprintIndex(storage_path=storage)
            index.observe_fingerprints(["fp_atomic_1", "fp_atomic_2"])
            assert storage.exists()
            # Reload and verify data survived
            index2 = FindingFingerprintIndex(storage_path=storage)
            assert len(index2) == 2
            assert index2.get("fp_atomic_1") is not None
            assert index2.get("fp_atomic_2") is not None
            # No .tmp file lingering
            tmp_file = storage.with_suffix(f"{storage.suffix}.tmp")
            assert not tmp_file.exists()
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_persist_multiple_times_no_tmp_residue(self):
        td = Path(tempfile.mkdtemp(prefix="fp_idx_multi_"))
        try:
            storage = td / "multi.json"
            index = FindingFingerprintIndex(storage_path=storage)
            for i in range(5):
                index.observe_fingerprints([f"fp_{i}"])
            assert len(index) == 5
            assert storage.exists()
            tmp_file = storage.with_suffix(f"{storage.suffix}.tmp")
            assert not tmp_file.exists()
        finally:
            shutil.rmtree(td, ignore_errors=True)