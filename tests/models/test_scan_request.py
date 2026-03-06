"""Edge-case focused tests for nocturna_engine.models.scan_request.ScanRequest."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.target import Target


def _target(**kw: object) -> Target:
    defaults: dict[str, object] = {"ip": "1.1.1.1"}
    defaults.update(kw)
    return Target(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# targets: min_length=1
# ---------------------------------------------------------------------------


class TestTargetsValidation:
    """targets list must have at least one entry."""

    def test_empty_targets_raises(self) -> None:
        with pytest.raises(ValidationError, match="too_short"):
            ScanRequest(targets=[])

    def test_single_target_valid(self) -> None:
        sr = ScanRequest(targets=[_target()])
        assert len(sr.targets) == 1

    def test_multiple_targets_valid(self) -> None:
        sr = ScanRequest(targets=[_target(), _target(ip="2.2.2.2")])
        assert len(sr.targets) == 2

    def test_targets_missing_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest()  # type: ignore[call-arg]

    def test_nested_target_validation_propagates(self) -> None:
        """Invalid nested Target should bubble up."""
        with pytest.raises(ValidationError):
            ScanRequest(targets=[{"ip": None, "domain": None}])  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# tool_names normalization
# ---------------------------------------------------------------------------


class TestToolNamesNormalization:
    """normalize_tool_names edge cases."""

    def test_none_is_valid(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=None)
        assert sr.tool_names is None

    def test_lowercased(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["NMAP", "SQLMap"])
        assert sr.tool_names == ["nmap", "sqlmap"]

    def test_stripped(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["  nmap  "])
        assert sr.tool_names == ["nmap"]

    def test_duplicates_removed(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["nmap", "NMAP", "nmap"])
        assert sr.tool_names == ["nmap"]

    def test_empty_strings_filtered(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["", "  ", "nmap"])
        assert sr.tool_names == ["nmap"]

    def test_all_empty_returns_none(self) -> None:
        """All entries are empty/whitespace => normalized list is empty => returns None."""
        sr = ScanRequest(targets=[_target()], tool_names=["", "  "])
        assert sr.tool_names is None

    def test_order_preserved_after_dedup(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["zap", "nmap", "ZAP", "burp"])
        assert sr.tool_names == ["zap", "nmap", "burp"]

    def test_single_tool_name(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["nmap"])
        assert sr.tool_names == ["nmap"]

    def test_whitespace_and_case_combined(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["  NMAP  ", "  nmap  "])
        assert sr.tool_names == ["nmap"]


# ---------------------------------------------------------------------------
# timeout_seconds: gt=0.0, le=3600.0
# ---------------------------------------------------------------------------


class TestTimeoutSeconds:
    """Boundary conditions for timeout_seconds."""

    def test_default_is_60(self) -> None:
        sr = ScanRequest(targets=[_target()])
        assert sr.timeout_seconds == 60.0

    def test_zero_raises(self) -> None:
        with pytest.raises(ValidationError, match="greater_than"):
            ScanRequest(targets=[_target()], timeout_seconds=0.0)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], timeout_seconds=-1.0)

    def test_3600_valid(self) -> None:
        sr = ScanRequest(targets=[_target()], timeout_seconds=3600.0)
        assert sr.timeout_seconds == 3600.0

    def test_3601_raises(self) -> None:
        with pytest.raises(ValidationError, match="less_than_equal"):
            ScanRequest(targets=[_target()], timeout_seconds=3601.0)

    def test_very_small_positive_valid(self) -> None:
        sr = ScanRequest(targets=[_target()], timeout_seconds=0.001)
        assert sr.timeout_seconds == 0.001

    def test_just_above_zero(self) -> None:
        sr = ScanRequest(targets=[_target()], timeout_seconds=0.0001)
        assert sr.timeout_seconds > 0


# ---------------------------------------------------------------------------
# retries: ge=0, le=10
# ---------------------------------------------------------------------------


class TestRetries:
    """Boundary conditions for retries."""

    def test_default_is_2(self) -> None:
        sr = ScanRequest(targets=[_target()])
        assert sr.retries == 2

    def test_zero_valid(self) -> None:
        sr = ScanRequest(targets=[_target()], retries=0)
        assert sr.retries == 0

    def test_ten_valid(self) -> None:
        sr = ScanRequest(targets=[_target()], retries=10)
        assert sr.retries == 10

    def test_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], retries=-1)

    def test_eleven_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], retries=11)


# ---------------------------------------------------------------------------
# concurrency_limit: ge=1, le=128
# ---------------------------------------------------------------------------


class TestConcurrencyLimit:
    """Boundary conditions for concurrency_limit."""

    def test_default_is_4(self) -> None:
        sr = ScanRequest(targets=[_target()])
        assert sr.concurrency_limit == 4

    def test_one_valid(self) -> None:
        sr = ScanRequest(targets=[_target()], concurrency_limit=1)
        assert sr.concurrency_limit == 1

    def test_128_valid(self) -> None:
        sr = ScanRequest(targets=[_target()], concurrency_limit=128)
        assert sr.concurrency_limit == 128

    def test_zero_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], concurrency_limit=0)

    def test_129_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], concurrency_limit=129)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], concurrency_limit=-1)


# ---------------------------------------------------------------------------
# extra="forbid"
# ---------------------------------------------------------------------------


class TestScanRequestExtraForbid:
    """Unknown fields must raise."""

    def test_extra_field_raises(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            ScanRequest(targets=[_target()], unknown_thing=True)

    def test_extra_field_typo_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], timout_seconds=30)  # typo


# ---------------------------------------------------------------------------
# Serialization: to_json / from_json
# ---------------------------------------------------------------------------


class TestScanRequestSerialization:
    """to_json / from_json / model_dump round-trip."""

    def test_to_json_returns_string(self) -> None:
        sr = ScanRequest(targets=[_target()])
        j = sr.to_json()
        assert isinstance(j, str)
        data = json.loads(j)
        assert "request_id" in data

    def test_from_json_round_trip(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=["nmap"], timeout_seconds=120.0)
        sr2 = ScanRequest.from_json(sr.to_json())
        assert sr2.request_id == sr.request_id
        assert sr2.tool_names == sr.tool_names
        assert sr2.timeout_seconds == sr.timeout_seconds

    def test_from_json_invalid_json_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest.from_json("not valid json")

    def test_from_json_missing_targets_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest.from_json('{"request_id": "abc"}')

    def test_model_dump_contains_created_at(self) -> None:
        sr = ScanRequest(targets=[_target()])
        d = sr.model_dump()
        assert "created_at" in d

    def test_model_validate_from_dict(self) -> None:
        sr = ScanRequest(targets=[_target()])
        d = sr.model_dump()
        sr2 = ScanRequest.model_validate(d)
        assert sr2.request_id == sr.request_id

    def test_targets_serialized_nested(self) -> None:
        sr = ScanRequest(targets=[_target(domain="example.com")])
        data = json.loads(sr.to_json())
        assert data["targets"][0]["domain"] == "example.com"

    def test_json_preserves_tool_names_none(self) -> None:
        sr = ScanRequest(targets=[_target()], tool_names=None)
        sr2 = ScanRequest.from_json(sr.to_json())
        assert sr2.tool_names is None


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


class TestScanRequestDefaults:
    """Defaults are correct for optional fields."""

    def test_request_id_is_valid_uuid(self) -> None:
        sr = ScanRequest(targets=[_target()])
        UUID(sr.request_id)

    def test_options_default_empty_dict(self) -> None:
        sr = ScanRequest(targets=[_target()])
        assert sr.options == {}

    def test_metadata_default_empty_dict(self) -> None:
        sr = ScanRequest(targets=[_target()])
        assert sr.metadata == {}

    def test_created_at_is_utc(self) -> None:
        sr = ScanRequest(targets=[_target()])
        assert sr.created_at.tzinfo is not None


# ---------------------------------------------------------------------------
# validate_assignment=True
# ---------------------------------------------------------------------------


class TestScanRequestAssignment:
    """Post-construction assignment validation."""

    def test_assign_invalid_timeout_raises(self) -> None:
        sr = ScanRequest(targets=[_target()])
        with pytest.raises(ValidationError):
            sr.timeout_seconds = 0.0

    def test_assign_invalid_retries_raises(self) -> None:
        sr = ScanRequest(targets=[_target()])
        with pytest.raises(ValidationError):
            sr.retries = -5

    def test_assign_valid_timeout_succeeds(self) -> None:
        sr = ScanRequest(targets=[_target()])
        sr.timeout_seconds = 300.0
        assert sr.timeout_seconds == 300.0

    def test_assign_empty_targets_raises(self) -> None:
        sr = ScanRequest(targets=[_target()])
        with pytest.raises(ValidationError):
            sr.targets = []


# ---------------------------------------------------------------------------
# Parametrized: timeout boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "timeout,should_pass",
    [
        (0.0, False),
        (-1.0, False),
        (-0.0001, False),
        (0.001, True),
        (1.0, True),
        (3600.0, True),
        (3600.001, False),
        (99999.0, False),
    ],
    ids=[
        "zero",
        "negative",
        "tiny_negative",
        "tiny_positive",
        "one",
        "max_3600",
        "just_over_max",
        "way_over_max",
    ],
)
def test_parametrized_timeout_boundaries(timeout: float, should_pass: bool) -> None:
    if should_pass:
        sr = ScanRequest(targets=[_target()], timeout_seconds=timeout)
        assert sr.timeout_seconds == timeout
    else:
        with pytest.raises(ValidationError):
            ScanRequest(targets=[_target()], timeout_seconds=timeout)
