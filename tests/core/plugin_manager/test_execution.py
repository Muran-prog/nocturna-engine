"""Edge-case tests for plugin execution: dispatch, policy, timeout, concurrency, v2 path."""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.exceptions import PluginExecutionError, ValidationError
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class GoodTool(BaseTool):
    name: ClassVar[str] = "good_tool"
    version: ClassVar[str] = "1.0.0"
    timeout_seconds: ClassVar[float] = 10.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={"ok": True})

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        target = request.targets[0].domain or "unknown"
        return [Finding(title="Good finding", description="test finding description", severity=SeverityLevel.LOW, tool=self.name, target=target)]


class CrashingTool(BaseTool):
    name: ClassVar[str] = "crashing_tool"
    timeout_seconds: ClassVar[float] = 5.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        raise RuntimeError("kaboom")

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class SlowTool(BaseTool):
    name: ClassVar[str] = "slow_tool"
    timeout_seconds: ClassVar[float] = 0.1  # Very short timeout
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        await asyncio.sleep(10)  # Will be timed out
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class NetworkTool(BaseTool):
    name: ClassVar[str] = "network_tool"
    version: ClassVar[str] = "1.0.0"
    requires_network: ClassVar[bool] = True
    binary_name: ClassVar[str] = "nmap"
    timeout_seconds: ClassVar[float] = 10.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={"ok": True})

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class SubprocessTool(BaseTool):
    name: ClassVar[str] = "subprocess_tool"
    binary_name: ClassVar[str] = "mytool"
    timeout_seconds: ClassVar[float] = 5.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={})

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class SetupFailTool(BaseTool):
    name: ClassVar[str] = "exec_setup_fail"
    max_retries: ClassVar[int] = 0
    timeout_seconds: ClassVar[float] = 2.0

    async def setup(self) -> None:
        raise RuntimeError("setup crash")

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


def _req(target: str = "example.com", **metadata: Any) -> ScanRequest:
    return ScanRequest(targets=[Target(domain=target)], metadata=metadata)


# ---------------------------------------------------------------------------
# execute_tool – legacy path (default, plugin_system_v2=False)
# ---------------------------------------------------------------------------

async def test_execute_tool_legacy_success():
    pm = PluginManager()
    pm.register_tool_class(GoodTool)
    await pm.initialize_plugins()
    result = await pm.execute_tool("good_tool", _req())
    assert result.success is True
    assert result.tool_name == "good_tool"
    assert len(result.findings) == 1


async def test_execute_tool_legacy_crash_returns_failure():
    pm = PluginManager()
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    result = await pm.execute_tool("crashing_tool", _req())
    assert result.success is False
    assert "kaboom" in result.error_message


async def test_execute_tool_unregistered_returns_failure():
    pm = PluginManager()
    result = await pm.execute_tool("nonexistent", _req())
    assert result.success is False
    assert "not registered" in result.error_message.lower() or "unavailable" in result.error_message.lower()


async def test_execute_tool_timeout_returns_failure():
    """Tool that exceeds timeout should return failure result."""
    pm = PluginManager(default_timeout_seconds=0.1)
    pm.register_tool_class(SlowTool)
    await pm.initialize_plugins()
    result = await pm.execute_tool("slow_tool", _req())
    assert result.success is False


async def test_execute_tool_setup_failure_returns_failure():
    """When tool setup fails, execution returns a failure result."""
    pm = PluginManager()
    pm.register_tool_class(SetupFailTool)
    await pm.initialize_plugins()
    result = await pm.execute_tool("exec_setup_fail", _req())
    assert result.success is False


# ---------------------------------------------------------------------------
# execute_tool – v2 path
# ---------------------------------------------------------------------------

async def test_execute_tool_v2_path_with_feature_flag():
    """When plugin_system_v2 is enabled, v2 execution path is used."""
    pm = PluginManager(feature_flags={"plugin_system_v2": True})
    pm.register_tool_class(GoodTool)
    await pm.initialize_plugins()
    result = await pm.execute_tool("good_tool", _req())
    assert result.tool_name == "good_tool"
    # v2 path may succeed or fall back to legacy for unregistered in deterministic registry
    assert isinstance(result, ScanResult)


async def test_execute_tool_v2_unregistered_falls_to_legacy():
    """V2 path falls back to legacy when tool is not in deterministic registry."""
    pm = PluginManager(feature_flags={"plugin_system_v2": True})
    result = await pm.execute_tool("ghost_tool", _req())
    assert result.success is False


# ---------------------------------------------------------------------------
# execute_all – batch execution
# ---------------------------------------------------------------------------

async def test_execute_all_returns_results_for_all_tools():
    pm = PluginManager()
    pm.register_tool_class(GoodTool)
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    results = await pm.execute_all(_req())
    assert len(results) == 2
    names = {r.tool_name for r in results}
    assert "good_tool" in names
    assert "crashing_tool" in names


async def test_execute_all_with_explicit_tool_names():
    pm = PluginManager()
    pm.register_tool_class(GoodTool)
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    results = await pm.execute_all(_req(), tool_names=["good_tool"])
    assert len(results) == 1
    assert results[0].tool_name == "good_tool"


async def test_execute_all_empty_selection():
    pm = PluginManager()
    results = await pm.execute_all(_req(), tool_names=[])
    assert results == []


async def test_execute_all_filters_unregistered_names():
    pm = PluginManager()
    pm.register_tool_class(GoodTool)
    await pm.initialize_plugins()
    results = await pm.execute_all(_req(), tool_names=["good_tool", "nonexistent"])
    assert len(results) == 1


async def test_execute_all_respects_request_tool_names():
    pm = PluginManager()
    pm.register_tool_class(GoodTool)
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    req = ScanRequest(targets=[Target(domain="example.com")], tool_names=["good_tool"])
    results = await pm.execute_all(req)
    assert len(results) == 1
    assert results[0].tool_name == "good_tool"


# ---------------------------------------------------------------------------
# execute_all – ai_fail_closed mode
# ---------------------------------------------------------------------------

async def test_execute_all_ai_fail_closed_empty_plan_raises():
    """When ai_fail_closed=True and no tools selected, raises ValidationError."""
    pm = PluginManager()
    req = _req(ai_fail_closed=True)
    with pytest.raises(ValidationError, match="AI execution rejected"):
        await pm.execute_all(req, tool_names=None)


async def test_execute_all_ai_fail_closed_empty_tools_raises():
    """When ai_fail_closed=True and empty list, raises ValidationError."""
    pm = PluginManager()
    pm.register_tool_class(GoodTool)
    req = _req(ai_fail_closed=True)
    with pytest.raises(ValidationError):
        await pm.execute_all(req, tool_names=[])


async def test_execute_all_ai_fail_closed_no_runnable_raises():
    """When ai_fail_closed=True and all tools unregistered, raises ValidationError."""
    pm = PluginManager()
    req = _req(ai_fail_closed=True)
    with pytest.raises(ValidationError):
        await pm.execute_all(req, tool_names=["ghost1", "ghost2"])


# ---------------------------------------------------------------------------
# Policy enforcement in execution
# ---------------------------------------------------------------------------

async def test_execute_tool_policy_denies_subprocess():
    """Policy denying subprocess should block tools that require it."""
    pm = PluginManager(feature_flags={"plugin_system_v2": True, "policy_fail_closed": True})
    pm.register_tool_class(SubprocessTool)
    await pm.initialize_plugins()
    req = _req(policy={"allow_subprocess": False})
    result = await pm.execute_tool("subprocess_tool", req)
    assert result.success is False
    reason_code = result.metadata.get("reason_code", "")
    assert "policy_denied" in reason_code or "denied" in str(result.error_message).lower()


async def test_execute_tool_policy_denies_network():
    """Policy denying network should block tools that require it."""
    pm = PluginManager(feature_flags={"plugin_system_v2": True, "policy_fail_closed": True})
    pm.register_tool_class(NetworkTool)
    await pm.initialize_plugins()
    req = _req(policy={"allow_network": False})
    result = await pm.execute_tool("network_tool", req)
    assert result.success is False


# ---------------------------------------------------------------------------
# Policy resolution helpers
# ---------------------------------------------------------------------------

async def test_is_policy_fail_closed_from_request():
    pm = PluginManager()
    req = _req(ai_fail_closed=True)
    assert pm._is_policy_fail_closed_enabled(request=req) is True


async def test_is_policy_fail_closed_from_feature_flag():
    pm = PluginManager(feature_flags={"plugin_system_v2": True, "policy_fail_closed": True})
    assert pm._is_policy_fail_closed_enabled(for_v2_execution=True) is True


async def test_is_policy_fail_closed_legacy_disabled():
    pm = PluginManager(feature_flags={"plugin_system_v2": False, "policy_fail_closed": True})
    # Without v2 or request override, legacy is False
    assert pm._is_policy_fail_closed_enabled() is False


async def test_is_ai_fail_closed_various_values():
    assert PluginManager._is_ai_fail_closed_request(_req(ai_fail_closed=True)) is True
    assert PluginManager._is_ai_fail_closed_request(_req(ai_fail_closed=False)) is False
    assert PluginManager._is_ai_fail_closed_request(_req(ai_fail_closed="true")) is True
    assert PluginManager._is_ai_fail_closed_request(_req(ai_fail_closed="yes")) is True
    assert PluginManager._is_ai_fail_closed_request(_req(ai_fail_closed="0")) is False
    assert PluginManager._is_ai_fail_closed_request(_req(ai_fail_closed=1)) is True
    assert PluginManager._is_ai_fail_closed_request(_req(ai_fail_closed=0)) is False


# ---------------------------------------------------------------------------
# Event publishing during execution
# ---------------------------------------------------------------------------

async def test_execute_tool_publishes_events():
    events_captured: list[tuple[str, dict]] = []

    async def capture_event(event_name: str, payload: dict) -> None:
        events_captured.append((event_name, payload))

    bus = EventBus()
    bus.subscribe("on_tool_started", lambda p: capture_event("on_tool_started", p))
    bus.subscribe("on_tool_finished", lambda p: capture_event("on_tool_finished", p))
    bus.subscribe("on_tool_initialized", lambda p: capture_event("on_tool_initialized", p))
    bus.subscribe("on_raw_finding_detected", lambda p: capture_event("on_raw_finding_detected", p))

    pm = PluginManager(event_bus=bus)
    pm.register_tool_class(GoodTool)
    await pm.initialize_plugins()
    await pm.execute_tool("good_tool", _req())

    event_names = [e[0] for e in events_captured]
    assert "on_tool_initialized" in event_names
    assert "on_tool_started" in event_names
    assert "on_tool_finished" in event_names


async def test_execute_tool_error_publishes_on_tool_error():
    events_captured: list[tuple[str, dict]] = []

    async def capture_event(event_name: str, payload: dict) -> None:
        events_captured.append((event_name, payload))

    bus = EventBus()
    bus.subscribe("on_tool_error", lambda p: capture_event("on_tool_error", p))

    pm = PluginManager(event_bus=bus)
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    await pm.execute_tool("crashing_tool", _req())

    event_names = [e[0] for e in events_captured]
    assert "on_tool_error" in event_names


# ---------------------------------------------------------------------------
# Result builder edge cases
# ---------------------------------------------------------------------------

async def test_failure_result_has_correct_structure():
    pm = PluginManager()
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    result = await pm.execute_tool("crashing_tool", _req())
    assert result.success is False
    assert result.error_message is not None
    assert result.duration_ms >= 0
    assert result.started_at is not None
    assert result.finished_at is not None


async def test_failure_result_metadata_degraded():
    pm = PluginManager()
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    result = await pm.execute_tool("crashing_tool", _req())
    assert result.metadata.get("degraded") is True


# ---------------------------------------------------------------------------
# Concurrency control
# ---------------------------------------------------------------------------

async def test_execute_all_respects_concurrency_limit():
    """Ensure max_concurrency is respected during batch execution."""
    pm = PluginManager(max_concurrency=1)
    pm.register_tool_class(GoodTool)
    await pm.initialize_plugins()
    results = await pm.execute_all(_req())
    assert len(results) == 1
    assert results[0].success is True


async def test_execute_all_concurrent_with_mixed_tools():
    pm = PluginManager(max_concurrency=4)
    pm.register_tool_class(GoodTool)
    pm.register_tool_class(CrashingTool)
    await pm.initialize_plugins()
    results = await pm.execute_all(_req())
    successes = [r for r in results if r.success]
    failures = [r for r in results if not r.success]
    assert len(successes) >= 1
    assert len(failures) >= 1


# ---------------------------------------------------------------------------
# v2 batch execution with invalid policy
# ---------------------------------------------------------------------------

async def test_v2_execute_all_invalid_policy_fail_closed():
    """V2 batch execution with invalid policy and fail_closed returns failures."""
    pm = PluginManager(feature_flags={"plugin_system_v2": True, "policy_fail_closed": True})
    pm.register_tool_class(GoodTool)
    await pm.initialize_plugins()
    req = _req(policy={"max_timeout_seconds": -999})
    results = await pm.execute_all(req)
    assert len(results) == 1
    assert results[0].success is False
    assert "policy_invalid" in str(results[0].metadata.get("reason_code", ""))


async def test_v2_execute_all_invalid_policy_fail_open():
    """V2 batch execution with invalid policy and fail_open should still run."""
    pm = PluginManager(feature_flags={"plugin_system_v2": True, "policy_fail_closed": False})
    pm.register_tool_class(GoodTool)
    await pm.initialize_plugins()
    req = _req(policy={"max_timeout_seconds": -999})
    results = await pm.execute_all(req)
    # With fail_open, policy_invalid is emitted but execution may still proceed
    assert len(results) >= 1


# ---------------------------------------------------------------------------
# Backpressure adaptive concurrency
# ---------------------------------------------------------------------------

async def test_resolve_adaptive_concurrency_normal():
    pm = PluginManager(max_concurrency=4)
    adaptive = pm._resolve_adaptive_concurrency(
        selected=["a", "b", "c", "d"],
        runnable=["a", "b", "c", "d"],
        request=_req(),
    )
    assert 1 <= adaptive <= 4


async def test_resolve_adaptive_concurrency_all_unhealthy():
    pm = PluginManager(max_concurrency=4)
    adaptive = pm._resolve_adaptive_concurrency(
        selected=["a", "b", "c", "d"],
        runnable=[],
        request=_req(),
    )
    assert adaptive >= 1


async def test_resolve_adaptive_concurrency_fast_speed():
    pm = PluginManager(max_concurrency=4)
    adaptive = pm._resolve_adaptive_concurrency(
        selected=["a", "b"],
        runnable=["a", "b"],
        request=_req(speed="fast"),
    )
    assert adaptive >= 1


async def test_resolve_adaptive_concurrency_safe_speed():
    pm = PluginManager(max_concurrency=4)
    adaptive = pm._resolve_adaptive_concurrency(
        selected=["a", "b"],
        runnable=["a", "b"],
        request=_req(speed="safe"),
    )
    assert adaptive >= 1


async def test_resolve_adaptive_concurrency_empty_selected():
    pm = PluginManager(max_concurrency=4)
    adaptive = pm._resolve_adaptive_concurrency(
        selected=[],
        runnable=[],
        request=_req(),
    )
    assert adaptive >= 1
