"""Edge-case tests for NormalizationConfig and NormalizationResult models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.detector import DetectionResult, InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.normalization.pipeline import NormalizationConfig, NormalizationResult
from nocturna_engine.normalization.severity import SeverityMap, build_severity_map


# ---------------------------------------------------------------------------
# NormalizationConfig model validation
# ---------------------------------------------------------------------------


class TestNormalizationConfigToolName:
    """tool_name: str, min_length=1."""

    def test_valid_tool_name(self) -> None:
        cfg = NormalizationConfig(tool_name="semgrep")
        assert cfg.tool_name == "semgrep"

    def test_single_char_tool_name(self) -> None:
        cfg = NormalizationConfig(tool_name="x")
        assert cfg.tool_name == "x"

    def test_empty_tool_name_raises(self) -> None:
        with pytest.raises(ValidationError, match="tool_name"):
            NormalizationConfig(tool_name="")

    def test_missing_tool_name_raises(self) -> None:
        with pytest.raises(ValidationError, match="tool_name"):
            NormalizationConfig()  # type: ignore[call-arg]


class TestNormalizationConfigExtra:
    """extra='forbid' and validate_assignment."""

    def test_extra_field_forbidden(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            NormalizationConfig(tool_name="t", bogus="nope")  # type: ignore[call-arg]

    def test_validate_assignment_rejects_bad_type(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        with pytest.raises(ValidationError):
            cfg.deduplicate = "not_a_bool"  # type: ignore[assignment]

    def test_validate_assignment_allows_valid_mutation(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        cfg.deduplicate = False
        assert cfg.deduplicate is False

    def test_validate_assignment_tool_name_min_length(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        with pytest.raises(ValidationError):
            cfg.tool_name = ""


class TestNormalizationConfigOptionalFields:
    """format_hint, tool_hint, target_hint optional fields."""

    def test_format_hint_default_none(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.format_hint is None

    def test_format_hint_set(self) -> None:
        cfg = NormalizationConfig(tool_name="t", format_hint="sarif")
        assert cfg.format_hint == "sarif"

    def test_tool_hint_default_none(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.tool_hint is None

    def test_tool_hint_set(self) -> None:
        cfg = NormalizationConfig(tool_name="t", tool_hint="nuclei")
        assert cfg.tool_hint == "nuclei"

    def test_target_hint_default_none(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.target_hint is None

    def test_source_reference_default_none(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.source_reference is None


class TestNormalizationConfigMaxErrors:
    """max_errors: int | None, ge=1."""

    def test_max_errors_default_none(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.max_errors is None

    def test_max_errors_valid_1(self) -> None:
        cfg = NormalizationConfig(tool_name="t", max_errors=1)
        assert cfg.max_errors == 1

    def test_max_errors_valid_large(self) -> None:
        cfg = NormalizationConfig(tool_name="t", max_errors=9999)
        assert cfg.max_errors == 9999

    def test_max_errors_zero_raises(self) -> None:
        with pytest.raises(ValidationError, match="max_errors"):
            NormalizationConfig(tool_name="t", max_errors=0)

    def test_max_errors_negative_raises(self) -> None:
        with pytest.raises(ValidationError, match="max_errors"):
            NormalizationConfig(tool_name="t", max_errors=-1)

    def test_max_errors_none_allowed(self) -> None:
        cfg = NormalizationConfig(tool_name="t", max_errors=None)
        assert cfg.max_errors is None


class TestNormalizationConfigMaxErrorRate:
    """max_error_rate: float | None, gt=0.0, le=1.0."""

    def test_max_error_rate_default_none(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.max_error_rate is None

    def test_max_error_rate_valid_half(self) -> None:
        cfg = NormalizationConfig(tool_name="t", max_error_rate=0.5)
        assert cfg.max_error_rate == 0.5

    def test_max_error_rate_valid_1_0(self) -> None:
        cfg = NormalizationConfig(tool_name="t", max_error_rate=1.0)
        assert cfg.max_error_rate == 1.0

    def test_max_error_rate_valid_tiny(self) -> None:
        cfg = NormalizationConfig(tool_name="t", max_error_rate=0.001)
        assert cfg.max_error_rate == 0.001

    def test_max_error_rate_zero_raises(self) -> None:
        with pytest.raises(ValidationError, match="max_error_rate"):
            NormalizationConfig(tool_name="t", max_error_rate=0.0)

    def test_max_error_rate_negative_raises(self) -> None:
        with pytest.raises(ValidationError, match="max_error_rate"):
            NormalizationConfig(tool_name="t", max_error_rate=-0.1)

    def test_max_error_rate_above_1_raises(self) -> None:
        with pytest.raises(ValidationError, match="max_error_rate"):
            NormalizationConfig(tool_name="t", max_error_rate=1.01)

    def test_max_error_rate_none_allowed(self) -> None:
        cfg = NormalizationConfig(tool_name="t", max_error_rate=None)
        assert cfg.max_error_rate is None


class TestNormalizationConfigDefaults:
    """Default values for remaining fields."""

    def test_deduplicate_default_true(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.deduplicate is True

    def test_preserve_raw_default_true(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.preserve_raw is True

    def test_severity_map_default(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert isinstance(cfg.severity_map, SeverityMap)

    def test_parser_options_default_empty(self) -> None:
        cfg = NormalizationConfig(tool_name="t")
        assert cfg.parser_options == {}

    def test_custom_severity_map(self) -> None:
        sm = build_severity_map(strict=True)
        cfg = NormalizationConfig(tool_name="t", severity_map=sm)
        assert cfg.severity_map.strict is True

    def test_parser_options_set(self) -> None:
        cfg = NormalizationConfig(tool_name="t", parser_options={"key": "val"})
        assert cfg.parser_options == {"key": "val"}


# ---------------------------------------------------------------------------
# NormalizationResult model validation
# ---------------------------------------------------------------------------


class TestNormalizationResultDefaults:
    """NormalizationResult default field values."""

    def test_all_defaults(self) -> None:
        result = NormalizationResult()
        assert result.findings == []
        assert result.issues == []
        assert isinstance(result.stats, NormalizationStats)
        assert result.detection is None
        assert result.parser_name == ""
        assert result.aborted is False
        assert result.abort_reason is None

    def test_extra_field_forbidden(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            NormalizationResult(bogus=True)  # type: ignore[call-arg]


class TestNormalizationResultWithData:
    """NormalizationResult with populated fields."""

    def test_with_findings(self) -> None:
        f = Finding(
            title="Test finding",
            description="desc text",
            severity=SeverityLevel.HIGH,
            tool="tool",
            target="example.com",
        )
        result = NormalizationResult(findings=[f])
        assert len(result.findings) == 1
        assert result.findings[0].title == "Test finding"

    def test_with_issues(self) -> None:
        issue = ParseIssue(message="something went wrong")
        result = NormalizationResult(issues=[issue])
        assert len(result.issues) == 1
        assert result.issues[0].message == "something went wrong"

    def test_with_detection(self) -> None:
        det = DetectionResult(
            format=InputFormat.SARIF,
            confidence=0.95,
            method="test",
        )
        result = NormalizationResult(detection=det)
        assert result.detection is not None
        assert result.detection.format == InputFormat.SARIF

    def test_with_stats(self) -> None:
        stats = NormalizationStats(
            total_records_processed=10,
            findings_produced=8,
            errors_encountered=2,
        )
        result = NormalizationResult(stats=stats)
        assert result.stats.total_records_processed == 10
        assert result.stats.error_rate == 0.2

    def test_aborted_with_reason(self) -> None:
        result = NormalizationResult(aborted=True, abort_reason="Too many errors")
        assert result.aborted is True
        assert result.abort_reason == "Too many errors"

    def test_parser_name_set(self) -> None:
        result = NormalizationResult(parser_name="sarif")
        assert result.parser_name == "sarif"

    def test_aborted_false_reason_none(self) -> None:
        result = NormalizationResult(aborted=False, abort_reason=None)
        assert result.aborted is False
        assert result.abort_reason is None
