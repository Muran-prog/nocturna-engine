"""Edge-case focused tests for nocturna_engine.models.scan_result.ScanResult."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_result import ScanResult


def _finding(**kw: object) -> Finding:
    defaults: dict[str, object] = {
        "title": "Test finding",
        "description": "Edge case",
        "tool": "scanner",
        "target": "example.com",
        "severity": SeverityLevel.INFO,
    }
    defaults.update(kw)
    return Finding(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Required fields: request_id, tool_name
# ---------------------------------------------------------------------------


class TestRequiredFields:
    """request_id and tool_name are required and min_length=1."""

    def test_missing_request_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(tool_name="nmap")  # type: ignore[call-arg]

    def test_missing_tool_name_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(request_id="abc")  # type: ignore[call-arg]

    def test_empty_request_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(request_id="", tool_name="nmap")

    def test_empty_tool_name_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(request_id="abc", tool_name="")

    def test_whitespace_only_request_id_raises(self) -> None:
        """min_length=1 check — whitespace counts as characters for min_length."""
        # Pydantic min_length counts len(" ") = 1 so this passes; verify:
        sr = ScanResult(request_id=" ", tool_name="nmap")
        assert sr.request_id == " "

    def test_single_char_request_id_valid(self) -> None:
        sr = ScanResult(request_id="x", tool_name="nmap")
        assert sr.request_id == "x"

    def test_single_char_tool_name_valid(self) -> None:
        sr = ScanResult(request_id="abc", tool_name="n")
        assert sr.tool_name == "n"


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


class TestScanResultDefaults:
    """Default field values must be sensible."""

    def test_result_id_is_valid_uuid(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        UUID(sr.result_id)

    def test_success_default_true(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.success is True

    def test_duration_ms_default_zero(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.duration_ms == 0

    def test_raw_output_default_none(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.raw_output is None

    def test_findings_default_empty_list(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.findings == []

    def test_error_message_default_none(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.error_message is None

    def test_metadata_default_empty_dict(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.metadata == {}

    def test_started_at_is_utc(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.started_at.tzinfo is not None

    def test_finished_at_is_utc(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap")
        assert sr.finished_at.tzinfo is not None


# ---------------------------------------------------------------------------
# success / failure states
# ---------------------------------------------------------------------------


class TestSuccessFailureStates:
    """success flag and error_message interaction."""

    def test_success_true_no_error(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", success=True)
        assert sr.success is True and sr.error_message is None

    def test_failure_with_error_message(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", success=False, error_message="timeout")
        assert sr.success is False and sr.error_message == "timeout"

    def test_success_with_error_message_allowed(self) -> None:
        """Model doesn't prevent success=True + error_message (no cross-validation)."""
        sr = ScanResult(request_id="r", tool_name="t", success=True, error_message="warning")
        assert sr.success is True and sr.error_message == "warning"

    def test_failure_no_error_message_allowed(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", success=False)
        assert sr.success is False and sr.error_message is None


# ---------------------------------------------------------------------------
# duration_ms: ge=0
# ---------------------------------------------------------------------------


class TestDurationMs:
    """Duration boundary conditions."""

    def test_zero_valid(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", duration_ms=0)
        assert sr.duration_ms == 0

    def test_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(request_id="r", tool_name="t", duration_ms=-1)

    def test_large_value_valid(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", duration_ms=999_999_999)
        assert sr.duration_ms == 999_999_999


# ---------------------------------------------------------------------------
# raw_output polymorphic type
# ---------------------------------------------------------------------------


class TestRawOutputTypes:
    """raw_output accepts dict | list | str | None."""

    def test_dict_raw_output(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output={"key": "val"})
        assert sr.raw_output == {"key": "val"}

    def test_list_raw_output(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output=[1, 2, 3])
        assert sr.raw_output == [1, 2, 3]

    def test_string_raw_output(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output="raw text")
        assert sr.raw_output == "raw text"

    def test_none_raw_output(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output=None)
        assert sr.raw_output is None

    def test_nested_dict_raw_output(self) -> None:
        nested = {"a": {"b": [1, 2, {"c": True}]}}
        sr = ScanResult(request_id="r", tool_name="t", raw_output=nested)
        assert sr.raw_output == nested

    def test_empty_dict_raw_output(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output={})
        assert sr.raw_output == {}

    def test_empty_list_raw_output(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output=[])
        assert sr.raw_output == []

    def test_empty_string_raw_output(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output="")
        assert sr.raw_output == ""


# ---------------------------------------------------------------------------
# findings list with nested Finding validation
# ---------------------------------------------------------------------------


class TestFindings:
    """Nested findings validation."""

    def test_single_finding(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", findings=[_finding()])
        assert len(sr.findings) == 1

    def test_multiple_findings(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", findings=[_finding(), _finding(title="Another finding")])
        assert len(sr.findings) == 2

    def test_invalid_nested_finding_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(
                request_id="r",
                tool_name="t",
                findings=[{"title": "", "description": "", "tool": "", "target": ""}],  # type: ignore[list-item]
            )

    def test_findings_preserve_fingerprints(self) -> None:
        f = _finding()
        sr = ScanResult(request_id="r", tool_name="t", findings=[f])
        assert sr.findings[0].fingerprint == f.fingerprint


# ---------------------------------------------------------------------------
# extra="forbid"
# ---------------------------------------------------------------------------


class TestScanResultExtraForbid:
    """Unknown fields must be rejected."""

    def test_extra_field_raises(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            ScanResult(request_id="r", tool_name="t", unknown_field=42)

    def test_multiple_extra_fields_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(request_id="r", tool_name="t", foo=1, bar=2)


# ---------------------------------------------------------------------------
# Serialization: to_json / from_json
# ---------------------------------------------------------------------------


class TestScanResultSerialization:
    """to_json / from_json / model_dump round-trip."""

    def test_to_json_returns_valid_json(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t")
        data = json.loads(sr.to_json())
        assert data["request_id"] == "r"
        assert data["tool_name"] == "t"

    def test_from_json_round_trip(self) -> None:
        sr = ScanResult(request_id="req-1", tool_name="nmap", duration_ms=500, success=False, error_message="err")
        sr2 = ScanResult.from_json(sr.to_json())
        assert sr2.request_id == sr.request_id
        assert sr2.duration_ms == sr.duration_ms
        assert sr2.success is False
        assert sr2.error_message == "err"

    def test_from_json_invalid_json_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult.from_json("<<<not json>>>")

    def test_from_json_missing_required_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult.from_json('{"result_id": "x"}')

    def test_round_trip_with_findings(self) -> None:
        f = _finding()
        sr = ScanResult(request_id="r", tool_name="t", findings=[f])
        sr2 = ScanResult.from_json(sr.to_json())
        assert len(sr2.findings) == 1
        assert sr2.findings[0].fingerprint == f.fingerprint

    def test_model_dump_contains_all_fields(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t")
        d = sr.model_dump()
        expected_keys = {
            "result_id", "request_id", "tool_name", "success", "started_at",
            "finished_at", "duration_ms", "raw_output", "findings", "error_message", "metadata",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_model_validate_from_dict(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t")
        sr2 = ScanResult.model_validate(sr.model_dump())
        assert sr2.result_id == sr.result_id

    def test_json_raw_output_dict_preserved(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output={"key": [1, 2]})
        sr2 = ScanResult.from_json(sr.to_json())
        assert sr2.raw_output == {"key": [1, 2]}

    def test_json_raw_output_string_preserved(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output="raw text output")
        sr2 = ScanResult.from_json(sr.to_json())
        assert sr2.raw_output == "raw text output"

    def test_json_raw_output_none_preserved(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", raw_output=None)
        sr2 = ScanResult.from_json(sr.to_json())
        assert sr2.raw_output is None


# ---------------------------------------------------------------------------
# validate_assignment=True
# ---------------------------------------------------------------------------


class TestScanResultAssignment:
    """Post-construction assignment validation."""

    def test_assign_negative_duration_raises(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t")
        with pytest.raises(ValidationError):
            sr.duration_ms = -10

    def test_assign_valid_duration_succeeds(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t")
        sr.duration_ms = 1500
        assert sr.duration_ms == 1500

    def test_assign_empty_request_id_raises(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t")
        with pytest.raises(ValidationError):
            sr.request_id = ""

    def test_assign_empty_tool_name_raises(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t")
        with pytest.raises(ValidationError):
            sr.tool_name = ""


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


class TestTimestamps:
    """Timestamp edge cases."""

    def test_custom_started_at(self) -> None:
        ts = datetime(2020, 6, 15, 12, 0, 0, tzinfo=UTC)
        sr = ScanResult(request_id="r", tool_name="t", started_at=ts)
        assert sr.started_at == ts

    def test_custom_finished_at(self) -> None:
        ts = datetime(2020, 6, 15, 12, 5, 0, tzinfo=UTC)
        sr = ScanResult(request_id="r", tool_name="t", finished_at=ts)
        assert sr.finished_at == ts

    def test_finished_before_started_allowed(self) -> None:
        """Model does not enforce started < finished (no cross-validator)."""
        early = datetime(2020, 1, 1, tzinfo=UTC)
        late = datetime(2025, 1, 1, tzinfo=UTC)
        sr = ScanResult(request_id="r", tool_name="t", started_at=late, finished_at=early)
        assert sr.started_at > sr.finished_at


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestScanResultMetadata:
    """Metadata edge cases."""

    def test_unicode_metadata(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", metadata={"名前": "テスト", "emoji": "🔒"})
        assert sr.metadata["名前"] == "テスト"

    def test_nested_metadata_preserved(self) -> None:
        meta = {"a": {"b": {"c": [1, 2, 3]}}}
        sr = ScanResult(request_id="r", tool_name="t", metadata=meta)
        assert sr.metadata == meta

    def test_metadata_with_none_value(self) -> None:
        sr = ScanResult(request_id="r", tool_name="t", metadata={"key": None})
        assert sr.metadata["key"] is None
