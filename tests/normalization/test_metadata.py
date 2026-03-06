"""Edge-case tests for nocturna_engine.normalization.metadata and errors.py."""

from __future__ import annotations

from datetime import UTC, datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from nocturna_engine.exceptions import NocturnaError
from nocturna_engine.normalization.errors import (
    FormatDetectionError,
    NormalizationError,
    ParseError,
    ParserNotFoundError,
    ParserRegistrationError,
    SeverityMappingError,
    StreamExhaustedError,
)
from nocturna_engine.normalization.metadata import (
    NormalizationOrigin,
    NormalizationStats,
    attach_normalization_origin,
)


# ===========================================================================
# Error hierarchy tests
# ===========================================================================


class TestErrorHierarchy:
    """All 7 normalization error classes exist and inherit correctly."""

    @pytest.mark.parametrize(
        "cls",
        [
            NormalizationError,
            FormatDetectionError,
            ParserNotFoundError,
            ParserRegistrationError,
            ParseError,
            SeverityMappingError,
            StreamExhaustedError,
        ],
    )
    def test_is_subclass_of_nocturna_error(self, cls: type) -> None:
        assert issubclass(cls, NocturnaError)

    @pytest.mark.parametrize(
        "cls",
        [
            FormatDetectionError,
            ParserNotFoundError,
            ParserRegistrationError,
            ParseError,
            SeverityMappingError,
            StreamExhaustedError,
        ],
    )
    def test_is_subclass_of_normalization_error(self, cls: type) -> None:
        assert issubclass(cls, NormalizationError)

    def test_normalization_error_is_exception(self) -> None:
        assert issubclass(NormalizationError, Exception)


# ---------------------------------------------------------------------------
# Error default_code and default_category
# ---------------------------------------------------------------------------


class TestErrorDefaults:
    """Each error class has correct default_code and default_category."""

    @pytest.mark.parametrize(
        "cls,expected_code,expected_category",
        [
            (NormalizationError, "normalization_error", "normalization"),
            (FormatDetectionError, "format_detection_error", "normalization_detection"),
            (ParserNotFoundError, "parser_not_found", "normalization_registry"),
            (ParserRegistrationError, "parser_registration_error", "normalization_registry"),
            (ParseError, "parse_error", "normalization_parsing"),
            (SeverityMappingError, "severity_mapping_error", "normalization_severity"),
            (StreamExhaustedError, "stream_exhausted", "normalization_streaming"),
        ],
    )
    def test_default_code_and_category(
        self, cls: type, expected_code: str, expected_category: str
    ) -> None:
        err = cls("test message")
        assert err.code == expected_code
        assert err.category == expected_category

    def test_stream_exhausted_default_retryable(self) -> None:
        err = StreamExhaustedError("stream died")
        assert err.retryable is True

    def test_parse_error_default_not_retryable(self) -> None:
        err = ParseError("bad data")
        assert err.retryable is False

    def test_normalization_error_default_not_retryable(self) -> None:
        err = NormalizationError("generic failure")
        assert err.retryable is False


# ---------------------------------------------------------------------------
# ParseError — context merging
# ---------------------------------------------------------------------------


class TestParseError:
    """ParseError init edge cases with line_number and source_parser."""

    def test_line_number_in_context(self) -> None:
        err = ParseError("bad line", line_number=42)
        assert err.line_number == 42
        assert err.context["line_number"] == 42

    def test_source_parser_in_context(self) -> None:
        err = ParseError("parser fail", source_parser="sarif_parser")
        assert err.source_parser == "sarif_parser"
        assert err.context["source_parser"] == "sarif_parser"

    def test_both_line_and_parser_in_context(self) -> None:
        err = ParseError("err", line_number=10, source_parser="csv_parser")
        ctx = err.context
        assert ctx["line_number"] == 10
        assert ctx["source_parser"] == "csv_parser"

    def test_no_line_or_parser_no_extra_context(self) -> None:
        err = ParseError("plain error")
        assert err.line_number is None
        assert err.source_parser is None
        assert "line_number" not in err.context
        assert "source_parser" not in err.context

    def test_existing_context_merged(self) -> None:
        err = ParseError(
            "err",
            line_number=5,
            source_parser="xml_parser",
            context={"extra_key": "extra_val"},
        )
        ctx = err.context
        assert ctx["line_number"] == 5
        assert ctx["source_parser"] == "xml_parser"
        assert ctx["extra_key"] == "extra_val"

    def test_context_without_line_or_parser(self) -> None:
        err = ParseError("err", context={"foo": "bar"})
        ctx = err.context
        assert ctx["foo"] == "bar"
        assert "line_number" not in ctx

    def test_code_override(self) -> None:
        err = ParseError("custom", code="custom_parse_error")
        assert err.code == "custom_parse_error"

    def test_category_override(self) -> None:
        err = ParseError("custom", category="custom_cat")
        assert err.category == "custom_cat"

    def test_retryable_override(self) -> None:
        err = ParseError("retry me", retryable=True)
        assert err.retryable is True

    def test_remediation(self) -> None:
        err = ParseError("fix this", remediation="Check your input format.")
        assert err.remediation == "Check your input format."

    def test_message_default_to_code(self) -> None:
        err = ParseError()
        assert str(err) == "parse_error"

    def test_str_representation(self) -> None:
        err = ParseError("Something broke at line 5")
        assert "Something broke at line 5" in str(err)


# ---------------------------------------------------------------------------
# Error remediation defaults
# ---------------------------------------------------------------------------


class TestErrorRemediation:
    """Remediation defaults on specific error classes."""

    def test_format_detection_has_remediation(self) -> None:
        err = FormatDetectionError("cannot detect")
        assert err.remediation is not None
        assert "format_hint" in err.remediation

    def test_parser_not_found_has_remediation(self) -> None:
        err = ParserNotFoundError("no parser")
        assert err.remediation is not None

    def test_parser_registration_has_remediation(self) -> None:
        err = ParserRegistrationError("dup name")
        assert err.remediation is not None

    def test_severity_mapping_has_remediation(self) -> None:
        err = SeverityMappingError("unknown severity")
        assert err.remediation is not None

    def test_stream_exhausted_has_remediation(self) -> None:
        err = StreamExhaustedError("stream dead")
        assert err.remediation is not None


# ---------------------------------------------------------------------------
# Error to_error_dict
# ---------------------------------------------------------------------------


class TestErrorSerialization:
    """Errors serialize to dicts for events/metadata."""

    def test_to_error_dict_keys(self) -> None:
        err = NormalizationError("test")
        d = err.to_error_dict()
        assert set(d.keys()) == {"code", "category", "retryable", "remediation", "context"}

    def test_parse_error_to_error_dict_context(self) -> None:
        err = ParseError("oops", line_number=7, source_parser="my_parser")
        d = err.to_error_dict()
        assert d["context"]["line_number"] == 7
        assert d["context"]["source_parser"] == "my_parser"


# ===========================================================================
# NormalizationOrigin model tests
# ===========================================================================


class TestNormalizationOrigin:
    """NormalizationOrigin pydantic model edge cases."""

    def test_valid_construction(self) -> None:
        origin = NormalizationOrigin(
            parser_name="sarif_parser",
            tool_name="semgrep",
            source_format="sarif",
        )
        assert origin.parser_name == "sarif_parser"
        assert origin.tool_name == "semgrep"
        assert origin.source_format == "sarif"

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            NormalizationOrigin(
                parser_name="p",
                tool_name="t",
                source_format="f",
                bogus="nope",
            )

    @pytest.mark.parametrize("field", ["parser_name", "tool_name", "source_format"])
    def test_min_length_1_required_fields(self, field: str) -> None:
        kwargs: dict[str, Any] = {
            "parser_name": "p",
            "tool_name": "t",
            "source_format": "f",
        }
        kwargs[field] = ""  # empty string should fail min_length=1
        with pytest.raises(ValidationError):
            NormalizationOrigin(**kwargs)

    def test_optional_fields_default_none(self) -> None:
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        assert origin.source_reference is None
        assert origin.original_severity is None
        assert origin.original_record is None
        assert origin.line_number is None

    def test_line_number_ge_1(self) -> None:
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f", line_number=1
        )
        assert origin.line_number == 1

    @pytest.mark.parametrize("bad_line", [0, -1, -100])
    def test_line_number_below_1_rejected(self, bad_line: int) -> None:
        with pytest.raises(ValidationError):
            NormalizationOrigin(
                parser_name="p",
                tool_name="t",
                source_format="f",
                line_number=bad_line,
            )

    def test_normalized_at_defaults_to_utc_now(self) -> None:
        before = datetime.now(UTC)
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        after = datetime.now(UTC)
        assert before <= origin.normalized_at <= after

    def test_normalized_at_is_utc(self) -> None:
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        assert origin.normalized_at.tzinfo is not None

    def test_normalized_at_custom_value(self) -> None:
        custom_dt = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        origin = NormalizationOrigin(
            parser_name="p",
            tool_name="t",
            source_format="f",
            normalized_at=custom_dt,
        )
        assert origin.normalized_at == custom_dt

    def test_all_optional_fields_filled(self) -> None:
        origin = NormalizationOrigin(
            parser_name="sarif_parser",
            tool_name="semgrep",
            source_format="sarif",
            source_reference="/tmp/scan.sarif",
            original_severity="WARNING",
            original_record={"ruleId": "xss-001", "level": "warning"},
            line_number=42,
        )
        assert origin.source_reference == "/tmp/scan.sarif"
        assert origin.original_severity == "WARNING"
        assert origin.original_record == {"ruleId": "xss-001", "level": "warning"}
        assert origin.line_number == 42

    def test_model_dump_mode_json(self) -> None:
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        dumped = origin.model_dump(mode="json")
        assert isinstance(dumped, dict)
        assert isinstance(dumped["normalized_at"], str)  # datetime serialized


# ===========================================================================
# NormalizationStats model tests
# ===========================================================================


class TestNormalizationStats:
    """NormalizationStats pydantic model edge cases."""

    def test_defaults_all_zero(self) -> None:
        stats = NormalizationStats()
        assert stats.total_records_processed == 0
        assert stats.findings_produced == 0
        assert stats.records_skipped == 0
        assert stats.errors_encountered == 0
        assert stats.duplicates_merged == 0
        assert stats.duration_seconds == 0.0

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            NormalizationStats(unknown_field=5)

    @pytest.mark.parametrize(
        "field",
        [
            "total_records_processed",
            "findings_produced",
            "records_skipped",
            "errors_encountered",
            "duplicates_merged",
        ],
    )
    def test_negative_int_rejected(self, field: str) -> None:
        with pytest.raises(ValidationError):
            NormalizationStats(**{field: -1})

    def test_negative_duration_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NormalizationStats(duration_seconds=-0.001)

    def test_zero_duration_accepted(self) -> None:
        stats = NormalizationStats(duration_seconds=0.0)
        assert stats.duration_seconds == 0.0

    def test_validate_assignment_enabled(self) -> None:
        stats = NormalizationStats()
        stats.total_records_processed = 10  # should work
        assert stats.total_records_processed == 10
        with pytest.raises(ValidationError):
            stats.total_records_processed = -1  # type: ignore[assignment]

    def test_validate_assignment_duration(self) -> None:
        stats = NormalizationStats()
        stats.duration_seconds = 5.5
        assert stats.duration_seconds == 5.5
        with pytest.raises(ValidationError):
            stats.duration_seconds = -1.0  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# NormalizationStats — error_rate property
# ---------------------------------------------------------------------------


class TestNormalizationStatsErrorRate:
    """error_rate edge cases."""

    def test_zero_records_returns_zero(self) -> None:
        stats = NormalizationStats()
        assert stats.error_rate == 0.0

    def test_no_errors(self) -> None:
        stats = NormalizationStats(total_records_processed=100, errors_encountered=0)
        assert stats.error_rate == 0.0

    def test_all_errors(self) -> None:
        stats = NormalizationStats(total_records_processed=50, errors_encountered=50)
        assert stats.error_rate == 1.0

    def test_partial_errors(self) -> None:
        stats = NormalizationStats(total_records_processed=200, errors_encountered=50)
        assert stats.error_rate == pytest.approx(0.25)

    def test_one_record_one_error(self) -> None:
        stats = NormalizationStats(total_records_processed=1, errors_encountered=1)
        assert stats.error_rate == 1.0


# ---------------------------------------------------------------------------
# NormalizationStats — success_rate property
# ---------------------------------------------------------------------------


class TestNormalizationStatsSuccessRate:
    """success_rate edge cases."""

    def test_zero_records_returns_zero(self) -> None:
        stats = NormalizationStats()
        assert stats.success_rate == 0.0

    def test_all_findings(self) -> None:
        stats = NormalizationStats(
            total_records_processed=100, findings_produced=100
        )
        assert stats.success_rate == 1.0

    def test_partial_success(self) -> None:
        stats = NormalizationStats(
            total_records_processed=200, findings_produced=150
        )
        assert stats.success_rate == pytest.approx(0.75)

    def test_no_findings(self) -> None:
        stats = NormalizationStats(total_records_processed=50, findings_produced=0)
        assert stats.success_rate == 0.0

    def test_success_rate_with_one_record(self) -> None:
        stats = NormalizationStats(
            total_records_processed=1, findings_produced=1
        )
        assert stats.success_rate == 1.0


# ===========================================================================
# attach_normalization_origin
# ===========================================================================


class TestAttachNormalizationOrigin:
    """attach_normalization_origin edge cases."""

    def test_returns_new_dict(self) -> None:
        original: dict[str, Any] = {"existing_key": "value"}
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        result = attach_normalization_origin(original, origin)
        assert result is not original

    def test_does_not_mutate_input(self) -> None:
        original: dict[str, Any] = {"existing_key": "value"}
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        attach_normalization_origin(original, origin)
        assert "_normalization" not in original

    def test_adds_normalization_key(self) -> None:
        origin = NormalizationOrigin(
            parser_name="sarif_parser", tool_name="semgrep", source_format="sarif"
        )
        result = attach_normalization_origin({}, origin)
        assert "_normalization" in result

    def test_normalization_value_is_dict(self) -> None:
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        result = attach_normalization_origin({}, origin)
        assert isinstance(result["_normalization"], dict)

    def test_normalization_contains_origin_fields(self) -> None:
        origin = NormalizationOrigin(
            parser_name="csv_parser",
            tool_name="nikto",
            source_format="csv",
            line_number=10,
            original_severity="HIGH",
        )
        result = attach_normalization_origin({}, origin)
        norm = result["_normalization"]
        assert norm["parser_name"] == "csv_parser"
        assert norm["tool_name"] == "nikto"
        assert norm["source_format"] == "csv"
        assert norm["line_number"] == 10
        assert norm["original_severity"] == "HIGH"

    def test_preserves_existing_metadata(self) -> None:
        original: dict[str, Any] = {"key1": "val1", "key2": 42}
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        result = attach_normalization_origin(original, origin)
        assert result["key1"] == "val1"
        assert result["key2"] == 42
        assert "_normalization" in result

    def test_empty_metadata_input(self) -> None:
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        result = attach_normalization_origin({}, origin)
        assert len(result) == 1
        assert "_normalization" in result

    def test_overwrites_existing_normalization_key(self) -> None:
        original: dict[str, Any] = {"_normalization": "old_value"}
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        result = attach_normalization_origin(original, origin)
        assert result["_normalization"] != "old_value"
        assert isinstance(result["_normalization"], dict)

    def test_model_dump_mode_json_serialization(self) -> None:
        origin = NormalizationOrigin(
            parser_name="p", tool_name="t", source_format="f"
        )
        result = attach_normalization_origin({}, origin)
        # normalized_at should be serialized as string in json mode
        assert isinstance(result["_normalization"]["normalized_at"], str)
