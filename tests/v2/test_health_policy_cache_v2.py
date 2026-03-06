"""Tests for health-check orchestration, policy controls, and result cache."""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime, time
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import BaseModel

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.core.plugin_v2 import ScanResultCache, build_result_fingerprint
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class HealthAwareTool(BaseTool):
    name: ClassVar[str] = "health_aware_tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"ok": True},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []

    async def health_check(self) -> bool:
        return False


class NetworkTool(BaseTool):
    name: ClassVar[str] = "network_tool"
    requires_network: ClassVar[bool] = True
    calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        NetworkTool.calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"calls": NetworkTool.calls},
            findings=[
                Finding(
                    title="Network execution",
                    description="Executed network tool",
                    severity=SeverityLevel.INFO,
                    tool=self.name,
                    target=request.targets[0].domain or "unknown",
                )
            ],
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


class RetryBoundTool(BaseTool):
    name: ClassVar[str] = "retry_bound_tool"
    max_retries: ClassVar[int] = 5
    execute_calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        RetryBoundTool.execute_calls += 1
        raise ConnectionError("retry-bound-failure")

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


class SlowTool(BaseTool):
    name: ClassVar[str] = "slow_tool"
    timeout_seconds: ClassVar[float] = 5.0

    async def execute(self, request: ScanRequest) -> ScanResult:
        await asyncio.sleep(0.05)
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"slow": True},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


class LargeOutputTool(BaseTool):
    name: ClassVar[str] = "large_output_tool"
    execute_calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        LargeOutputTool.execute_calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"blob": "X" * 4096},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


class FingerprintMode(Enum):
    FAST = "fast"
    SAFE = "safe"


class FingerprintModel(BaseModel):
    profile: str
    issued_at: datetime


class FallbackOption:
    def __init__(self, value: str) -> None:
        self._value = value

    def __str__(self) -> str:
        return f"fallback:{self._value}"


def _manager() -> PluginManager:
    manager = PluginManager(event_bus=EventBus())
    manager.apply_runtime_config({"features": {"plugin_system_v2": True}})
    return manager


def _request(request_id: str = "req-v2") -> ScanRequest:
    return ScanRequest(
        request_id=request_id,
        targets=[Target(domain="example.com")],
        metadata={},
    )


def _non_json_options(*, reorder: bool = False) -> dict[str, Any]:
    issued_at = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
    if not reorder:
        return {
            "network_tool": {
                "output_path": Path("reports/network.json"),
                "timestamp": issued_at,
                "run_date": date(2025, 1, 2),
                "run_time": time(9, 15, 0),
                "mode": FingerprintMode.FAST,
                "profile": FingerprintModel(profile="strict", issued_at=issued_at),
                "ports": {443, 80},
                "nested": {"letters": {"b", "a"}, "limit": 3},
                "fallback": FallbackOption("alpha"),
            },
            "global_set": {"x", "y"},
        }
    return {
        "global_set": {"y", "x"},
        "network_tool": {
            "fallback": FallbackOption("alpha"),
            "nested": {"limit": 3, "letters": {"a", "b"}},
            "ports": {80, 443},
            "profile": FingerprintModel(profile="strict", issued_at=issued_at),
            "mode": FingerprintMode.FAST,
            "run_time": time(9, 15, 0),
            "run_date": date(2025, 1, 2),
            "timestamp": issued_at,
            "output_path": Path("reports/network.json"),
        },
    }


@pytest.mark.asyncio()
async def test_preflight_healthcheck_skips_unhealthy_plugin() -> None:
    manager = _manager()
    manager.register_tool_class(HealthAwareTool)

    status = await manager.preflight_health_check(request=_request(), tool_names=["health_aware_tool"])

    assert status["health_aware_tool"]["healthy"] is False
    assert status["health_aware_tool"]["reason"] in {"health_check_failed", "False", None}


@pytest.mark.asyncio()
async def test_policy_denies_network_execution() -> None:
    manager = _manager()
    manager.register_tool_class(NetworkTool)

    request = _request()
    request.metadata["policy"] = {"allow_network": False}
    result = await manager.execute_tool("network_tool", request)

    assert result.success is False
    assert result.metadata["reason"] == "policy_denied:network"


@pytest.mark.asyncio()
async def test_result_cache_reuses_previous_successful_execution() -> None:
    NetworkTool.calls = 0
    manager = _manager()
    manager.register_tool_class(NetworkTool)
    request1 = _request("req-cache-1")
    request1.metadata["policy"] = {"allow_network": True}
    request2 = _request("req-cache-2")
    request2.metadata["policy"] = {"allow_network": True}

    first = await manager.execute_tool("network_tool", request1)
    second = await manager.execute_tool("network_tool", request2)

    assert first.success is True
    assert second.success is True
    assert second.metadata["cache_hit"] is True
    assert NetworkTool.calls == 1


def test_build_result_fingerprint_is_deterministic_for_logically_equal_payload() -> None:
    request1 = _request("req-fingerprint-1")
    request1.options = _non_json_options(reorder=False)

    request2 = _request("req-fingerprint-2")
    request2.options = _non_json_options(reorder=True)

    fingerprint1 = build_result_fingerprint(
        request=request1,
        tool_name="network_tool",
        tool_version="1.0.0",
        policy_signature={"allow_cache": True, "limits": {"timeout": 30.0, "retries": 2}},
    )
    fingerprint2 = build_result_fingerprint(
        request=request2,
        tool_name="network_tool",
        tool_version="1.0.0",
        policy_signature={"limits": {"retries": 2, "timeout": 30.0}, "allow_cache": True},
    )

    assert fingerprint1 == fingerprint2


def test_build_result_fingerprint_changes_when_payload_changes() -> None:
    request1 = _request("req-fingerprint-change-1")
    request1.options = _non_json_options(reorder=False)

    request2 = _request("req-fingerprint-change-2")
    request2.options = _non_json_options(reorder=False)
    request2.options["network_tool"]["mode"] = FingerprintMode.SAFE

    fingerprint1 = build_result_fingerprint(
        request=request1,
        tool_name="network_tool",
        tool_version="1.0.0",
        policy_signature={"allow_cache": True},
    )
    fingerprint2 = build_result_fingerprint(
        request=request2,
        tool_name="network_tool",
        tool_version="1.0.0",
        policy_signature={"allow_cache": True},
    )

    assert fingerprint1 != fingerprint2


def test_build_result_fingerprint_accepts_non_json_option_types() -> None:
    request = _request("req-fingerprint-types")
    request.options = _non_json_options(reorder=False)

    fingerprint = build_result_fingerprint(
        request=request,
        tool_name="network_tool",
        tool_version="1.0.0",
        policy_signature={"allow_cache": True},
    )

    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 64


@pytest.mark.asyncio()
async def test_result_cache_reuses_execution_for_non_json_options() -> None:
    NetworkTool.calls = 0
    manager = _manager()
    manager.register_tool_class(NetworkTool)

    request1 = _request("req-cache-non-json-1")
    request1.metadata["policy"] = {"allow_network": True}
    request1.options = _non_json_options(reorder=False)
    request2 = _request("req-cache-non-json-2")
    request2.metadata["policy"] = {"allow_network": True}
    request2.options = _non_json_options(reorder=True)

    first = await manager.execute_tool("network_tool", request1)
    second = await manager.execute_tool("network_tool", request2)

    assert first.success is True
    assert second.success is True
    assert second.metadata["cache_hit"] is True
    assert NetworkTool.calls == 1


@pytest.mark.asyncio()
async def test_policy_retry_limit_is_enforced_at_runtime() -> None:
    RetryBoundTool.execute_calls = 0
    manager = _manager()
    manager.register_tool_class(RetryBoundTool)

    request = _request("req-retry-limit")
    request.retries = 3
    request.metadata["policy"] = {"max_retries": 1}
    result = await manager.execute_tool("retry_bound_tool", request)

    assert result.success is False
    assert RetryBoundTool.execute_calls == 2
    assert result.metadata["effective_retries"] == 1


@pytest.mark.asyncio()
async def test_policy_timeout_limit_is_enforced_at_runtime() -> None:
    manager = _manager()
    manager.register_tool_class(SlowTool)

    request = _request("req-timeout-limit")
    request.timeout_seconds = 2.0
    request.metadata["policy"] = {"max_timeout_seconds": 0.01, "max_retries": 0}
    result = await manager.execute_tool("slow_tool", request)

    assert result.success is False
    assert result.metadata["effective_timeout_seconds"] == pytest.approx(0.01)
    assert result.metadata["error"]["code"] == "timeout"


@pytest.mark.asyncio()
async def test_policy_output_limit_is_enforced_at_runtime() -> None:
    LargeOutputTool.execute_calls = 0
    manager = _manager()
    manager.register_tool_class(LargeOutputTool)

    request = _request("req-output-limit")
    request.metadata["policy"] = {"max_output_bytes": 256}
    result = await manager.execute_tool("large_output_tool", request)

    assert result.success is False
    assert result.metadata["reason_code"] == "output_limit_exceeded"
    assert result.metadata["error"]["code"] == "output_limit_exceeded"
    assert result.raw_output == {
        "truncated": True,
        "reason": "output_limit_exceeded",
        "observed_output_bytes": result.metadata["observed_output_bytes"],
        "effective_max_output_bytes": 256,
    }
    assert LargeOutputTool.execute_calls == 1


@pytest.mark.asyncio()
async def test_scan_result_cache_enforces_ttl_lru_and_metrics() -> None:
    clock_state = {"now": 0.0}

    def _clock() -> float:
        return float(clock_state["now"])

    cache = ScanResultCache(default_ttl_seconds=1.0, max_size=2, clock=_clock)

    await cache.set(
        "a",
        ScanResult(request_id="req-a", tool_name="cache-tool", raw_output={"value": "a"}),
    )
    assert (await cache.get("a")) is not None
    assert cache.metrics["cache_hit"] == 1

    assert (await cache.get("missing")) is None
    assert cache.metrics["cache_miss"] == 1

    await cache.set(
        "b",
        ScanResult(request_id="req-b", tool_name="cache-tool", raw_output={"value": "b"}),
    )
    await cache.set(
        "c",
        ScanResult(request_id="req-c", tool_name="cache-tool", raw_output={"value": "c"}),
    )

    assert (await cache.get("a")) is None
    assert cache.metrics["cache_evict"] >= 1

    clock_state["now"] = 5.0
    assert (await cache.get("b")) is None
    assert cache.metrics["cache_miss"] >= 2
