"""Edge-case focused tests for nocturna_engine.models.finding."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from nocturna_engine.models.finding import (
    FINGERPRINT_SCHEMA_VERSION,
    Finding,
    SeverityLevel,
    _canonical_json,
    _collect_normalized_keys,
    _collect_significant_evidence_values,
    _normalize_evidence_value,
    _normalize_token,
    build_finding_fingerprint,
)


# ---------------------------------------------------------------------------
# SeverityLevel enum
# ---------------------------------------------------------------------------


class TestSeverityLevel:
    """Exhaustive SeverityLevel enum tests."""

    def test_all_members_present(self) -> None:
        assert set(SeverityLevel) == {
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        }

    def test_values_are_lowercase_strings(self) -> None:
        for member in SeverityLevel:
            assert member.value == member.name.lower()

    def test_severity_is_str_subclass(self) -> None:
        assert isinstance(SeverityLevel.CRITICAL, str)

    def test_severity_string_equality(self) -> None:
        assert SeverityLevel.HIGH == "high"

    def test_severity_from_value(self) -> None:
        assert SeverityLevel("critical") is SeverityLevel.CRITICAL

    def test_invalid_severity_value_raises(self) -> None:
        with pytest.raises(ValueError):
            SeverityLevel("unknown")

    @pytest.mark.parametrize("level", list(SeverityLevel), ids=lambda s: s.name)
    def test_each_severity_in_finding(self, level: SeverityLevel) -> None:
        f = Finding(title="Test finding", description="desc edge", severity=level, tool="t", target="x.com")
        assert f.severity is level


# ---------------------------------------------------------------------------
# Finding text field validators
# ---------------------------------------------------------------------------


class TestFindingTextNormalization:
    """normalize_text edge cases for title, description, tool, target."""

    def test_title_stripped(self) -> None:
        f = Finding(title="  padded  ", description="abc", tool="t", target="x.com")
        assert f.title == "padded"

    def test_description_stripped(self) -> None:
        f = Finding(title="abc", description="  desc  ", tool="t", target="x.com")
        assert f.description == "desc"

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValidationError, match="Text fields must not be empty"):
            Finding(title="", description="ok desc", tool="t", target="x.com")

    def test_whitespace_only_title_raises(self) -> None:
        with pytest.raises(ValidationError, match="Text fields must not be empty"):
            Finding(title="   ", description="ok desc", tool="t", target="x.com")

    def test_title_too_short_after_trim_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="ab", description="desc ok", tool="t", target="x.com")

    def test_title_max_length_200(self) -> None:
        f = Finding(title="a" * 200, description="desc ok", tool="t", target="x.com")
        assert len(f.title) == 200

    def test_title_exceeding_200_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="a" * 201, description="desc ok", tool="t", target="x.com")

    def test_description_min_length_3(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="valid", description="ab", tool="t", target="x.com")

    def test_tool_empty_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="valid", description="desc ok", tool="", target="x.com")

    def test_tool_max_length_64(self) -> None:
        f = Finding(title="valid", description="desc ok", tool="t" * 64, target="x.com")
        assert len(f.tool) == 64

    def test_tool_exceeding_64_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="valid", description="desc ok", tool="t" * 65, target="x.com")

    def test_target_empty_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="valid", description="desc ok", tool="t", target="")

    def test_non_string_coerced_via_str(self) -> None:
        """normalize_text calls str(value); integer should work."""
        f = Finding(title="abc", description="desc ok", tool="123", target="x.com")
        assert f.tool == "123"


# ---------------------------------------------------------------------------
# CVSS boundary conditions
# ---------------------------------------------------------------------------


class TestCVSSBoundary:
    """cvss field ge=0.0, le=10.0."""

    def test_cvss_zero_valid(self) -> None:
        f = Finding(title="abc", description="desc ok", tool="t", target="x.com", cvss=0.0)
        assert f.cvss == 0.0

    def test_cvss_ten_valid(self) -> None:
        f = Finding(title="abc", description="desc ok", tool="t", target="x.com", cvss=10.0)
        assert f.cvss == 10.0

    def test_cvss_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="abc", description="desc ok", tool="t", target="x.com", cvss=-0.1)

    def test_cvss_over_ten_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(title="abc", description="desc ok", tool="t", target="x.com", cvss=10.1)

    def test_cvss_none_default(self) -> None:
        f = Finding(title="abc", description="desc ok", tool="t", target="x.com")
        assert f.cvss is None


# ---------------------------------------------------------------------------
# extra="forbid"
# ---------------------------------------------------------------------------


class TestFindingExtraForbid:
    """Unknown fields must be rejected."""

    def test_extra_field_raises(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            Finding(title="abc", description="desc ok", tool="t", target="x.com", bogus=1)


# ---------------------------------------------------------------------------
# Fingerprint: stability, determinism, collision resistance
# ---------------------------------------------------------------------------


class TestFingerprintStability:
    """Fingerprint must be deterministic and semantically stable."""

    def _make_finding(self, **overrides: object) -> Finding:
        defaults: dict[str, object] = dict(
            title="SQL Injection", description="Found SQLi", tool="sqlmap", target="example.com",
            severity=SeverityLevel.HIGH,
        )
        defaults.update(overrides)
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_fingerprint_is_64_char_hex(self) -> None:
        f = self._make_finding()
        assert len(f.fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in f.fingerprint)

    def test_fingerprint_deterministic_same_inputs(self) -> None:
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_differs_on_title_change(self) -> None:
        f1 = self._make_finding(title="SQL Injection")
        f2 = self._make_finding(title="XSS Stored")
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_ignores_severity_change(self) -> None:
        """Severity is excluded from fingerprint (v2) — same finding, different severity = same fp."""
        f1 = self._make_finding(severity=SeverityLevel.HIGH)
        f2 = self._make_finding(severity=SeverityLevel.LOW)
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_ignores_tool_change(self) -> None:
        """Tool is excluded from fingerprint (v2) — same finding from different tools = same fp."""
        f1 = self._make_finding(tool="sqlmap")
        f2 = self._make_finding(tool="nmap")
        assert f1.fingerprint == f2.fingerprint
    def test_fingerprint_differs_on_target_change(self) -> None:
        f1 = self._make_finding(target="example.com")
        f2 = self._make_finding(target="other.com")
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_differs_on_evidence_change(self) -> None:
        f1 = self._make_finding(evidence={"key": "val1"})
        f2 = self._make_finding(evidence={"key": "val2"})
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_ignores_finding_id(self) -> None:
        """Different finding_id same content => same fingerprint."""
        f1 = self._make_finding(finding_id="aaa")
        f2 = self._make_finding(finding_id="bbb")
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_ignores_created_at(self) -> None:
        f1 = self._make_finding(created_at=datetime(2020, 1, 1, tzinfo=UTC))
        f2 = self._make_finding(created_at=datetime(2025, 1, 1, tzinfo=UTC))
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_case_insensitive_title(self) -> None:
        """Titles 'SQL Injection' and 'sql injection' should produce same fingerprint."""
        f1 = self._make_finding(title="SQL Injection")
        f2 = self._make_finding(title="sql injection")
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_whitespace_insensitive_title(self) -> None:
        f1 = self._make_finding(title="SQL  Injection")
        f2 = self._make_finding(title="SQL Injection")
        assert f1.fingerprint == f2.fingerprint

    def test_semantic_fingerprint_alias(self) -> None:
        f = self._make_finding()
        assert f.semantic_fingerprint == f.fingerprint

    def test_fingerprint_with_cwe_vs_without(self) -> None:
        f1 = self._make_finding(cwe="CWE-89")
        f2 = self._make_finding(cwe=None)
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_cwe_case_insensitive(self) -> None:
        f1 = self._make_finding(cwe="CWE-89")
        f2 = self._make_finding(cwe="cwe-89")
        assert f1.fingerprint == f2.fingerprint


# ---------------------------------------------------------------------------
# build_finding_fingerprint standalone
# ---------------------------------------------------------------------------


class TestBuildFindingFingerprint:
    """Direct calls to the helper function."""

    def test_returns_sha256_hex(self) -> None:
        fp = build_finding_fingerprint(
            target="x", title="abc", cwe=None, evidence={},
        )
        assert len(fp) == 64

    def test_empty_evidence_dict(self) -> None:
        fp = build_finding_fingerprint(
            target="x", title="abc", cwe=None, evidence={},
        )
        assert isinstance(fp, str)

    def test_nested_evidence_dict(self) -> None:
        evidence = {"a": {"b": {"c": "deep"}}}
        fp = build_finding_fingerprint(
            target="x", title="abc", cwe=None, evidence=evidence,
        )
        assert len(fp) == 64


# ---------------------------------------------------------------------------
# _normalize_token helper
# ---------------------------------------------------------------------------


class TestNormalizeToken:
    """Edge cases of the token normalizer."""

    def test_collapses_whitespace(self) -> None:
        assert _normalize_token("  a   b  ") == "a b"

    def test_lowercase_default(self) -> None:
        assert _normalize_token("ABC") == "abc"

    def test_no_lowercase(self) -> None:
        assert _normalize_token("ABC", lowercase=False) == "ABC"

    def test_empty_string(self) -> None:
        assert _normalize_token("") == ""

    def test_non_string_converted(self) -> None:
        assert _normalize_token(42) == "42"


# ---------------------------------------------------------------------------
# _normalize_evidence_value helper
# ---------------------------------------------------------------------------


class TestNormalizeEvidenceValue:
    """Edge cases in evidence value normalization."""

    def test_none_returns_none(self) -> None:
        assert _normalize_evidence_value(None) is None

    def test_bool_preserved(self) -> None:
        assert _normalize_evidence_value(True) is True
        assert _normalize_evidence_value(False) is False

    def test_int_preserved(self) -> None:
        assert _normalize_evidence_value(42) == 42

    def test_float_rounded(self) -> None:
        assert _normalize_evidence_value(3.14159265) == 3.141593

    def test_inf_to_string(self) -> None:
        assert _normalize_evidence_value(float("inf")) == "inf"

    def test_neg_inf_to_string(self) -> None:
        assert _normalize_evidence_value(float("-inf")) == "-inf"

    def test_nan_to_string(self) -> None:
        assert _normalize_evidence_value(float("nan")) == "nan"

    def test_empty_string_returns_none(self) -> None:
        assert _normalize_evidence_value("") is None

    def test_whitespace_only_returns_none(self) -> None:
        assert _normalize_evidence_value("   ") is None

    def test_long_string_truncated_to_256(self) -> None:
        result = _normalize_evidence_value("x" * 300)
        assert isinstance(result, str) and len(result) == 256


# ---------------------------------------------------------------------------
# _collect_normalized_keys helper
# ---------------------------------------------------------------------------


class TestCollectNormalizedKeys:
    """Key collection traversal edge cases."""

    def test_empty_dict(self) -> None:
        assert _collect_normalized_keys({}) == set()

    def test_flat_dict(self) -> None:
        assert _collect_normalized_keys({"A": 1, "B": 2}) == {"a", "b"}

    def test_nested_dict(self) -> None:
        keys = _collect_normalized_keys({"outer": {"inner": 1}})
        assert "outer" in keys and "outer.inner" in keys

    def test_list_values_traversed(self) -> None:
        keys = _collect_normalized_keys({"items": [{"sub": 1}]})
        assert "items" in keys and "items.sub" in keys

    def test_empty_key_skipped(self) -> None:
        keys = _collect_normalized_keys({"": "val", "ok": 1})
        assert "" not in keys and "ok" in keys

    def test_whitespace_key_skipped(self) -> None:
        keys = _collect_normalized_keys({"   ": "val"})
        assert len(keys) == 0

    def test_scalar_returns_empty(self) -> None:
        assert _collect_normalized_keys("hello") == set()


# ---------------------------------------------------------------------------
# _collect_significant_evidence_values
# ---------------------------------------------------------------------------


class TestCollectSignificantEvidenceValues:
    """Evidence value collection edge cases."""

    def test_empty_dict(self) -> None:
        assert _collect_significant_evidence_values({}) == []

    def test_none_value_excluded(self) -> None:
        result = _collect_significant_evidence_values({"key": None})
        assert result == []

    def test_scalar_at_root(self) -> None:
        result = _collect_significant_evidence_values("hello")
        assert len(result) == 1 and result[0]["path"] == "root"

    def test_sorted_keys(self) -> None:
        result = _collect_significant_evidence_values({"b": 2, "a": 1})
        paths = [r["path"] for r in result]
        assert paths == ["a", "b"]


# ---------------------------------------------------------------------------
# Finding serialization
# ---------------------------------------------------------------------------


class TestFindingSerialization:
    """JSON round-trip and model_dump."""

    def _make(self) -> Finding:
        return Finding(
            title="Test XSS", description="Reflected XSS", severity=SeverityLevel.HIGH,
            tool="scanner", target="example.com", cvss=7.5,
        )

    def test_model_dump_json_parse(self) -> None:
        f = self._make()
        data = json.loads(f.model_dump_json())
        assert data["severity"] == "high"
        assert data["cvss"] == 7.5

    def test_model_validate_json_round_trip(self) -> None:
        f = self._make()
        f2 = Finding.model_validate_json(f.model_dump_json())
        assert f2.fingerprint == f.fingerprint
        assert f2.title == f.title

    def test_model_dump_includes_fingerprint(self) -> None:
        f = self._make()
        d = f.model_dump()
        assert "fingerprint" in d and len(d["fingerprint"]) == 64

    def test_finding_id_is_valid_uuid(self) -> None:
        f = self._make()
        UUID(f.finding_id)  # raises if invalid


# ---------------------------------------------------------------------------
# validate_assignment=True
# ---------------------------------------------------------------------------


class TestFindingAssignment:
    """Post-construction assignment validation."""

    def test_assigning_invalid_severity_raises(self) -> None:
        f = Finding(title="abc", description="desc ok", tool="t", target="x.com")
        with pytest.raises(ValidationError):
            f.severity = "invalid_level"  # type: ignore[assignment]

    def test_assigning_cvss_out_of_range_raises(self) -> None:
        f = Finding(title="abc", description="desc ok", tool="t", target="x.com", cvss=5.0)
        with pytest.raises(ValidationError):
            f.cvss = 11.0

    def test_assigning_valid_cvss_succeeds(self) -> None:
        f = Finding(title="abc", description="desc ok", tool="t", target="x.com", cvss=5.0)
        f.cvss = 9.8
        assert f.cvss == 9.8
