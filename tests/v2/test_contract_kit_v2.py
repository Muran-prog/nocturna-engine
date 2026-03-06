"""Tests for plugin contract test-kit utilities."""

from __future__ import annotations

from typing import Any, ClassVar

from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.testing import assert_plugin_contract


class ContractReadyTool(BaseTool):
    """Simple tool used for contract test-kit validation."""

    name: ClassVar[str] = "contract_ready_tool"
    version: ClassVar[str] = "3.2.1"
    supported_target_types: ClassVar[tuple[str, ...]] = ("domain",)
    supported_phases: ClassVar[tuple[str, ...]] = ("recon",)

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
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []


def test_contract_testkit_validates_manifest_and_expected_fields() -> None:
    report = assert_plugin_contract(
        ContractReadyTool,
        plugin_id="contract_ready_tool",
        version="3.2.1",
    )

    assert report.supported_targets == ("domain",)
    assert report.supported_phases == ("recon",)

