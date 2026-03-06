"""Tests for process-level isolated plugin execution."""

from __future__ import annotations

import asyncio
import time
from typing import Any, ClassVar

import pytest

from nocturna_engine.core.plugin_manager.execution.isolation import execute_tool_isolated
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Test tool doubles
# ---------------------------------------------------------------------------


class InProcessTool(BaseTool):
    """Default non-isolated tool — should run in the same process."""

    name: ClassVar[str] = "in_process_tool"
    version: ClassVar[str] = "1.0.0"
    isolated: ClassVar[bool] = False
    timeout_seconds: ClassVar[float] = 10.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"ok": True},
        )

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class IsolatedTool(BaseTool):
    """Isolated tool that returns a valid result from a subprocess."""

    name: ClassVar[str] = "isolated_tool"
    version: ClassVar[str] = "1.0.0"
    isolated: ClassVar[bool] = True
    timeout_seconds: ClassVar[float] = 30.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"isolated": True},
        )

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class IsolatedSlowTool(BaseTool):
    """Isolated tool that sleeps forever — should be killed by timeout."""

    name: ClassVar[str] = "isolated_slow_tool"
    version: ClassVar[str] = "1.0.0"
    isolated: ClassVar[bool] = True
    timeout_seconds: ClassVar[float] = 0.5
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        await asyncio.sleep(3600)  # Will be killed by timeout
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class IsolatedCrashTool(BaseTool):
    """Isolated tool that raises an unhandled exception."""

    name: ClassVar[str] = "isolated_crash_tool"
    version: ClassVar[str] = "1.0.0"
    isolated: ClassVar[bool] = True
    timeout_seconds: ClassVar[float] = 10.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        raise RuntimeError("boom from isolated process")

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _req(target: str = "example.com") -> ScanRequest:
    return ScanRequest(targets=[Target(domain=target)])


# ---------------------------------------------------------------------------
# Tests — BaseTool.isolated ClassVar
# ---------------------------------------------------------------------------


def test_non_isolated_tool_has_default_false():
    """BaseTool.isolated defaults to False."""
    assert InProcessTool.isolated is False


def test_isolated_tool_has_isolated_true():
    """Setting isolated=True on subclass is respected."""
    assert IsolatedTool.isolated is True


# ---------------------------------------------------------------------------
# Tests — serialization round-trips (required for isolation)
# ---------------------------------------------------------------------------


def test_scan_request_serialization_roundtrip():
    """ScanRequest survives model_dump_json / model_validate_json."""
    req = _req()
    json_str = req.model_dump_json()
    restored = ScanRequest.model_validate_json(json_str)
    assert restored.request_id == req.request_id
    assert len(restored.targets) == 1
    assert restored.targets[0].domain == "example.com"


def test_scan_result_serialization_roundtrip():
    """ScanResult survives model_dump_json / model_validate_json."""
    result = ScanResult(
        request_id="test-123",
        tool_name="test_tool",
        success=True,
        raw_output={"key": "value"},
    )
    json_str = result.model_dump_json()
    restored = ScanResult.model_validate_json(json_str)
    assert restored.request_id == result.request_id
    assert restored.tool_name == result.tool_name
    assert restored.success is True
    assert restored.raw_output == {"key": "value"}


# ---------------------------------------------------------------------------
# Tests — isolated execution via execute_tool_isolated
# ---------------------------------------------------------------------------


async def test_isolated_tool_returns_result():
    """Tool with isolated=True runs in subprocess and returns valid ScanResult."""
    req = _req()
    result = await execute_tool_isolated(IsolatedTool, req, timeout_seconds=30.0)
    assert isinstance(result, ScanResult)
    assert result.success is True
    assert result.request_id == req.request_id
    assert result.tool_name == "isolated_tool"


async def test_isolated_tool_timeout_returns_failure():
    """Tool that sleeps forever is killed after timeout and returns failure."""
    req = _req()
    start = time.monotonic()
    result = await execute_tool_isolated(IsolatedSlowTool, req, timeout_seconds=1.0)
    elapsed = time.monotonic() - start
    assert isinstance(result, ScanResult)
    assert result.success is False
    assert result.error_message is not None
    # Should not have waited the full sleep duration
    assert elapsed < 10.0


async def test_isolated_tool_crash_returns_failure():
    """Tool that raises gets a failure result (not an exception in the parent)."""
    req = _req()
    result = await execute_tool_isolated(IsolatedCrashTool, req, timeout_seconds=10.0)
    assert isinstance(result, ScanResult)
    assert result.success is False
    assert result.error_message is not None


async def test_non_isolated_tool_runs_in_process():
    """Default isolated=False means standard in-process execution (not routed to isolation)."""
    assert InProcessTool.isolated is False
    # Direct instantiation and execution — no subprocess involved
    tool = InProcessTool()
    req = _req()
    result = await tool.execute(req)
    assert result.success is True
    assert result.tool_name == "in_process_tool"
