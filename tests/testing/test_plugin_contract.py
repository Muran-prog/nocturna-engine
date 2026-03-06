"""Comprehensive edge-case tests for plugin contract validation."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.testing.plugin_contract import (
    PluginContractReport,
    assert_plugin_contract,
    validate_plugin_contract,
)


# ---------------------------------------------------------------------------
# Concrete BaseTool subclass test doubles
# ---------------------------------------------------------------------------


class ValidTool(BaseTool):
    """Minimal valid tool for happy-path contract testing."""

    name: ClassVar[str] = "valid-tool"
    version: ClassVar[str] = "1.0.0"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class ToolWithDisplayName(BaseTool):
    """Tool with explicit display_name attribute."""

    name: ClassVar[str] = "display-tool"
    version: ClassVar[str] = "2.0.0"
    display_name: ClassVar[str] = "My Display Tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class ToolWithPhases(BaseTool):
    """Tool declaring supported phases."""

    name: ClassVar[str] = "phase-tool"
    version: ClassVar[str] = "0.5.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("recon", "scan", "report")

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class ToolWithTargetTypes(BaseTool):
    """Tool declaring supported target types."""

    name: ClassVar[str] = "target-tool"
    version: ClassVar[str] = "0.3.0"
    supported_target_types: ClassVar[tuple[str, ...]] = ("host", "url", "cidr")

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class ToolWithNoName(BaseTool):
    """Tool with empty name, relying on class name fallback."""

    name: ClassVar[str] = ""
    version: ClassVar[str] = "1.0.0"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name="unnamed",
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class ToolWithOptionsModel(BaseTool):
    """Tool with a Pydantic options model for schema generation."""

    name: ClassVar[str] = "options-tool"
    version: ClassVar[str] = "1.0.0"

    from pydantic import BaseModel

    class ToolOptions(BaseModel):
        depth: int = 3
        verbose: bool = False

    options_model = ToolOptions

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class ToolWithBinaryName(BaseTool):
    """Tool that wraps an external binary."""

    name: ClassVar[str] = "binary-tool"
    version: ClassVar[str] = "1.0.0"
    binary_name: ClassVar[str] = "nmap"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class ToolWithMixedAttributes(BaseTool):
    """Tool with phases, targets, binary, and options."""

    name: ClassVar[str] = "mixed-tool"
    version: ClassVar[str] = "3.0.0"
    display_name: ClassVar[str] = "Mixed Tool"
    supported_phases: ClassVar[tuple[str, ...]] = ("scan",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("host",)
    binary_name: ClassVar[str] = "masscan"

    from pydantic import BaseModel

    class MixedOptions(BaseModel):
        rate: int = 1000

    options_model = MixedOptions

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# validate_plugin_contract: happy paths
# ---------------------------------------------------------------------------


def test_validate_valid_tool_returns_report() -> None:
    """validate_plugin_contract on valid tool should return PluginContractReport."""
    report = validate_plugin_contract(ValidTool)
    assert isinstance(report, PluginContractReport)
    assert report.plugin_id == "valid-tool"
    assert report.version == "1.0.0"


def test_validate_tool_with_display_name() -> None:
    """Tool with explicit display_name should be reflected in report."""
    report = validate_plugin_contract(ToolWithDisplayName)
    assert report.display_name == "My Display Tool"
    assert report.plugin_id == "display-tool"
    assert report.version == "2.0.0"


def test_validate_tool_with_phases() -> None:
    """Tool supported_phases should appear in report."""
    report = validate_plugin_contract(ToolWithPhases)
    assert "recon" in report.supported_phases
    assert "scan" in report.supported_phases
    assert "report" in report.supported_phases


def test_validate_tool_with_target_types() -> None:
    """Tool supported_target_types should appear in report as supported_targets."""
    report = validate_plugin_contract(ToolWithTargetTypes)
    assert "host" in report.supported_targets
    assert "url" in report.supported_targets
    assert "cidr" in report.supported_targets


def test_validate_tool_with_options_model_has_schema() -> None:
    """Tool with options_model should report has_option_schema=True."""
    report = validate_plugin_contract(ToolWithOptionsModel)
    assert report.has_option_schema is True


def test_validate_tool_without_options_model_has_no_schema() -> None:
    """Tool without options_model should report has_option_schema=False."""
    report = validate_plugin_contract(ValidTool)
    assert report.has_option_schema is False


def test_validate_tool_with_no_name_uses_class_fallback() -> None:
    """Tool with empty name should fall back to class name (lowered)."""
    report = validate_plugin_contract(ToolWithNoName)
    # The fallback uses the class name lowered: "toolwithnoname"
    assert report.plugin_id
    assert len(report.plugin_id) > 0


def test_validate_tool_with_binary_name() -> None:
    """Tool with binary_name should be valid and produce a report."""
    report = validate_plugin_contract(ToolWithBinaryName)
    assert report.plugin_id == "binary-tool"
    assert report.version == "1.0.0"


def test_validate_mixed_attributes_tool() -> None:
    """Tool with all attributes should validate and fill all report fields."""
    report = validate_plugin_contract(ToolWithMixedAttributes)
    assert report.plugin_id == "mixed-tool"
    assert report.version == "3.0.0"
    assert report.display_name == "Mixed Tool"
    assert report.has_option_schema is True
    assert "scan" in report.supported_phases
    assert "host" in report.supported_targets


# ---------------------------------------------------------------------------
# validate_plugin_contract: edge cases
# ---------------------------------------------------------------------------


def test_validate_tool_phases_are_sorted_and_lowered() -> None:
    """Phases should be normalized (lowercase, sorted, deduplicated)."""
    report = validate_plugin_contract(ToolWithPhases)
    phases = list(report.supported_phases)
    assert phases == sorted(phases)
    assert all(p == p.lower() for p in phases)


def test_validate_tool_targets_are_sorted_and_lowered() -> None:
    """Targets should be normalized (lowercase, sorted, deduplicated)."""
    report = validate_plugin_contract(ToolWithTargetTypes)
    targets = list(report.supported_targets)
    assert targets == sorted(targets)
    assert all(t == t.lower() for t in targets)


def test_validate_returns_frozen_report() -> None:
    """PluginContractReport should be frozen (immutable)."""
    report = validate_plugin_contract(ValidTool)
    with pytest.raises(AttributeError):
        report.plugin_id = "hacked"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# assert_plugin_contract: happy paths
# ---------------------------------------------------------------------------


def test_assert_contract_matching_fields() -> None:
    """assert_plugin_contract should pass when all expected fields match."""
    report = assert_plugin_contract(
        ValidTool,
        plugin_id="valid-tool",
        version="1.0.0",
    )
    assert isinstance(report, PluginContractReport)


def test_assert_contract_display_name_match() -> None:
    """assert_plugin_contract should pass on matching display_name."""
    report = assert_plugin_contract(
        ToolWithDisplayName,
        display_name="My Display Tool",
    )
    assert report.display_name == "My Display Tool"


def test_assert_contract_has_option_schema_match() -> None:
    """assert_plugin_contract should pass on matching has_option_schema."""
    assert_plugin_contract(ToolWithOptionsModel, has_option_schema=True)
    assert_plugin_contract(ValidTool, has_option_schema=False)


def test_assert_contract_no_expected_fields() -> None:
    """assert_plugin_contract with no expected fields should just validate."""
    report = assert_plugin_contract(ValidTool)
    assert report.plugin_id == "valid-tool"


# ---------------------------------------------------------------------------
# assert_plugin_contract: failures
# ---------------------------------------------------------------------------


def test_assert_contract_wrong_plugin_id_raises() -> None:
    """Mismatched plugin_id should raise AssertionError."""
    with pytest.raises(AssertionError, match="Contract mismatch.*plugin_id"):
        assert_plugin_contract(ValidTool, plugin_id="wrong-name")


def test_assert_contract_wrong_version_raises() -> None:
    """Mismatched version should raise AssertionError."""
    with pytest.raises(AssertionError, match="Contract mismatch.*version"):
        assert_plugin_contract(ValidTool, version="99.0.0")


def test_assert_contract_wrong_display_name_raises() -> None:
    """Mismatched display_name should raise AssertionError."""
    with pytest.raises(AssertionError, match="Contract mismatch.*display_name"):
        assert_plugin_contract(
            ToolWithDisplayName, display_name="Wrong Name"
        )


def test_assert_contract_wrong_has_option_schema_raises() -> None:
    """Mismatched has_option_schema should raise AssertionError."""
    with pytest.raises(AssertionError, match="Contract mismatch.*has_option_schema"):
        assert_plugin_contract(ValidTool, has_option_schema=True)


def test_assert_contract_nonexistent_field_raises() -> None:
    """Asserting on a field that doesn't exist on the report should raise."""
    with pytest.raises(AttributeError):
        assert_plugin_contract(ValidTool, nonexistent_field="value")


# ---------------------------------------------------------------------------
# PluginContractReport dataclass
# ---------------------------------------------------------------------------


def test_report_dataclass_fields() -> None:
    """PluginContractReport should have all expected fields."""
    report = PluginContractReport(
        plugin_id="test",
        display_name="Test",
        version="1.0.0",
        has_option_schema=False,
        supported_targets=("host",),
        supported_phases=("scan",),
    )
    assert report.plugin_id == "test"
    assert report.display_name == "Test"
    assert report.version == "1.0.0"
    assert report.has_option_schema is False
    assert report.supported_targets == ("host",)
    assert report.supported_phases == ("scan",)


def test_report_frozen_cannot_mutate() -> None:
    """PluginContractReport should be frozen."""
    report = PluginContractReport(
        plugin_id="test",
        display_name="Test",
        version="1.0.0",
        has_option_schema=False,
        supported_targets=(),
        supported_phases=(),
    )
    with pytest.raises(AttributeError):
        report.version = "2.0.0"  # type: ignore[misc]


def test_report_equality() -> None:
    """Two reports with same fields should be equal."""
    r1 = PluginContractReport(
        plugin_id="test",
        display_name="Test",
        version="1.0.0",
        has_option_schema=False,
        supported_targets=(),
        supported_phases=(),
    )
    r2 = PluginContractReport(
        plugin_id="test",
        display_name="Test",
        version="1.0.0",
        has_option_schema=False,
        supported_targets=(),
        supported_phases=(),
    )
    assert r1 == r2


def test_report_inequality_different_version() -> None:
    """Reports with different versions should not be equal."""
    r1 = PluginContractReport(
        plugin_id="test",
        display_name="Test",
        version="1.0.0",
        has_option_schema=False,
        supported_targets=(),
        supported_phases=(),
    )
    r2 = PluginContractReport(
        plugin_id="test",
        display_name="Test",
        version="2.0.0",
        has_option_schema=False,
        supported_targets=(),
        supported_phases=(),
    )
    assert r1 != r2


def test_report_empty_tuples_by_default() -> None:
    """Report with empty phases/targets should have empty tuples."""
    report = validate_plugin_contract(ValidTool)
    assert report.supported_targets == ()
    assert report.supported_phases == ()


# ---------------------------------------------------------------------------
# Multiple validations on same class
# ---------------------------------------------------------------------------


def test_validate_same_class_twice_is_idempotent() -> None:
    """Validating the same class twice should produce identical reports."""
    r1 = validate_plugin_contract(ValidTool)
    r2 = validate_plugin_contract(ValidTool)
    assert r1 == r2


def test_assert_contract_returns_report_on_success() -> None:
    """assert_plugin_contract should return the report on success."""
    report = assert_plugin_contract(ValidTool, plugin_id="valid-tool")
    assert isinstance(report, PluginContractReport)
    assert report.plugin_id == "valid-tool"
