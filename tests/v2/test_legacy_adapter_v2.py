"""Tests for legacy BaseTool adapter under plugin runtime v2."""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import structlog
import pytest

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_v2 import (
    EnvironmentSecretAccessor,
    InMemoryMetricsCollector,
    InMemoryRuntimeCache,
    LegacyToolAdapter,
    LocalTempStorageProvider,
    PluginRuntimeContext,
    build_manifest_from_tool_class,
)
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class LegacyDemoTool(BaseTool):
    """Legacy plugin without any v2-specific methods."""

    name: ClassVar[str] = "legacy_demo_tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"status": "ok"},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        return [
            Finding(
                title="Legacy finding",
                description="Parsed from legacy output",
                severity=SeverityLevel.INFO,
                tool=self.name,
                target=request.targets[0].domain or "unknown",
            )
        ]


class ApiOnlyTool(BaseTool):
    """Tool exposing API requirement without explicit requires_network flag."""

    name: ClassVar[str] = "api_only_tool"
    requires_api: ClassVar[bool] = True

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={})

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


class BinaryOnlyTool(BaseTool):
    """Tool exposing binary requirement without explicit filesystem flag."""

    name: ClassVar[str] = "binary_only_tool"
    binary_name: ClassVar[str] = "echo"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={})

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


def _runtime_context() -> PluginRuntimeContext:
    return PluginRuntimeContext(
        event_bus=EventBus(),
        logger=structlog.get_logger("adapter-test"),
        config={},
        secrets=EnvironmentSecretAccessor(),
        cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(),
        storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
        request_metadata={},
        policy={},
    )


@pytest.mark.asyncio()
async def test_legacy_adapter_executes_and_parses_findings() -> None:
    tool = LegacyDemoTool()
    manifest = build_manifest_from_tool_class(LegacyDemoTool)
    adapter = LegacyToolAdapter(tool_name=LegacyDemoTool.name, tool=tool, manifest=manifest)
    request = ScanRequest(targets=[Target(domain="example.com")])

    result = await adapter.execute(request, _runtime_context())

    assert result.success is True
    assert len(result.findings) == 1
    assert result.findings[0].title == "Legacy finding"


def test_manifest_infers_network_and_filesystem_requirements_without_downscoping() -> None:
    api_manifest = build_manifest_from_tool_class(ApiOnlyTool)
    binary_manifest = build_manifest_from_tool_class(BinaryOnlyTool)

    assert api_manifest.execution_requirements.network is True
    assert api_manifest.execution_requirements.filesystem is False
    assert binary_manifest.execution_requirements.subprocess is True
    assert binary_manifest.execution_requirements.filesystem is True
