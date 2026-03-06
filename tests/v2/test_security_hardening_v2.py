"""Security hardening tests for policy fail-closed and AI safe mode."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from nocturna_engine.core.engine import NocturnaEngine
from nocturna_engine.core.event_bus import Event, EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.exceptions import ValidationError
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class StaticV2ConfigService:
    """Config service fake with v2 runtime enabled."""

    def load(self) -> dict[str, Any]:
        return {
            "engine": {"max_concurrency": 4, "default_timeout_seconds": 30.0},
            "plugins": {"auto_discover_packages": []},
            "features": {
                "plugin_system_v2": True,
                "event_contract_v2": True,
                "ai_api_v2": True,
            },
        }

    def get(self, key: str, default: Any = None) -> Any:
        _ = key
        return default


class SubprocessBoundTool(BaseTool):
    """Tool that requires subprocess permission according to manifest."""

    name: ClassVar[str] = "subprocess_bound_tool"
    binary_name: ClassVar[str] = "echo"
    calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        SubprocessBoundTool.calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"calls": SubprocessBoundTool.calls},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []


class NetworkBoundTool(BaseTool):
    """Tool that requires network permission according to manifest."""

    name: ClassVar[str] = "network_bound_tool"
    requires_network: ClassVar[bool] = True
    calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        NetworkBoundTool.calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"calls": NetworkBoundTool.calls},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []



class UnrestrictedTool(BaseTool):
    """Tool that requires no restricted permissions (no subprocess, network, filesystem)."""

    name: ClassVar[str] = "unrestricted_tool"
    calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        UnrestrictedTool.calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"calls": UnrestrictedTool.calls},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []


def _request(*, request_id: str, policy: dict[str, Any] | None = None) -> ScanRequest:
    metadata: dict[str, Any] = {}
    if policy is not None:
        metadata["policy"] = policy
    return ScanRequest(
        request_id=request_id,
        targets=[Target(domain="example.com")],
        metadata=metadata,
    )


def _manager(*, policy_fail_closed: bool = True, event_bus: EventBus | None = None) -> PluginManager:
    manager = PluginManager(event_bus=event_bus or EventBus())
    manager.apply_runtime_config(
        {
            "features": {
                "plugin_system_v2": True,
                "policy_fail_closed": policy_fail_closed,
            }
        }
    )
    return manager


@pytest.mark.asyncio()
async def test_invalid_policy_is_denied_by_default_in_v2() -> None:
    SubprocessBoundTool.calls = 0
    manager = _manager()
    manager.register_tool_class(SubprocessBoundTool)

    result = await manager.execute_tool(
        "subprocess_bound_tool",
        _request(request_id="req-invalid-policy", policy={"max_retries": "not-an-int"}),
    )

    assert result.success is False
    assert result.error_message == "policy_invalid"
    assert result.metadata["reason"] == "policy_invalid"
    assert result.metadata["reason_code"] == "policy_invalid"
    assert isinstance(result.metadata.get("policy_error"), str)
    assert result.metadata["error"]["code"] == "policy_invalid"
    assert result.metadata["error"]["category"] == "policy"
    assert result.metadata["error"]["retryable"] is False
    assert SubprocessBoundTool.calls == 0


@pytest.mark.asyncio()
async def test_policy_fail_closed_flag_can_restore_fail_open_compatibility() -> None:
    UnrestrictedTool.calls = 0
    bus = EventBus()
    manager = _manager(policy_fail_closed=False, event_bus=bus)
    manager.register_tool_class(UnrestrictedTool)

    invalid_policy_events: list[Event] = []
    tool_errors: list[Event] = []

    async def on_policy_invalid(event: Event) -> None:
        invalid_policy_events.append(event)

    async def on_tool_error(event: Event) -> None:
        tool_errors.append(event)

    bus.subscribe("on_policy_invalid", on_policy_invalid)
    bus.subscribe("on_tool_error", on_tool_error)

    result = await manager.execute_tool(
        "unrestricted_tool",
        _request(request_id="req-invalid-policy-compat", policy={"max_retries": "not-an-int"}),
    )

    assert result.success is True
    assert result.metadata.get("reason") is None
    assert result.metadata.get("reason_code") is None
    assert invalid_policy_events
    fallback = invalid_policy_events[0].payload
    assert fallback["reason"] == "policy_invalid"
    assert fallback["reason_code"] == "policy_invalid"
    assert fallback["action"] == "fallback"
    assert fallback["tool"] == "unrestricted_tool"
    assert fallback["code"] == "policy_invalid"
    assert fallback["category"] == "policy"
    assert tool_errors == []
    assert UnrestrictedTool.calls == 1


@pytest.mark.asyncio()
async def test_ai_safe_mode_changes_policy_and_runtime_behavior() -> None:
    SubprocessBoundTool.calls = 0
    engine = NocturnaEngine(config_service=StaticV2ConfigService())
    engine.register_tool(SubprocessBoundTool)

    async with engine:
        fast_context = await engine.ai_scan("example.com", goal="recon", safe=False)
        with pytest.raises(ValidationError) as exc_info:
            await engine.ai_scan("example.com", goal="recon", safe=True)

    fast_result = next(item for item in fast_context["scan_results"] if item.tool_name == "subprocess_bound_tool")

    assert fast_context["request"].metadata["policy"]["allow_subprocess"] is True
    assert fast_result.success is True
    assert exc_info.value.code == "ai_plan_all_skipped"
    assert exc_info.value.context["plan"]["skipped"]["subprocess_bound_tool"] == "policy_denied:subprocess"
    assert SubprocessBoundTool.calls == 1


@pytest.mark.asyncio()
async def test_ai_safe_mode_blocks_network_bound_plugin_execution() -> None:
    NetworkBoundTool.calls = 0
    engine = NocturnaEngine(config_service=StaticV2ConfigService())
    engine.register_tool(NetworkBoundTool)

    async with engine:
        fast_context = await engine.ai_scan("example.com", goal="recon", safe=False)
        with pytest.raises(ValidationError) as exc_info:
            await engine.ai_scan("example.com", goal="recon", safe=True)

    fast_result = next(item for item in fast_context["scan_results"] if item.tool_name == "network_bound_tool")

    assert fast_context["request"].metadata["policy"]["allow_network"] is True
    assert fast_result.success is True
    assert exc_info.value.code == "ai_plan_all_skipped"
    assert exc_info.value.context["plan"]["skipped"]["network_bound_tool"] == "policy_denied:network"
    assert NetworkBoundTool.calls == 1



@pytest.mark.asyncio()
async def test_policy_refusal_reason_codes_are_present_in_metadata_and_events() -> None:
    bus = EventBus()
    manager = _manager(event_bus=bus)
    manager.register_tool_class(SubprocessBoundTool)

    tool_errors: list[Event] = []
    invalid_policy_events: list[Event] = []

    async def on_tool_error(event: Event) -> None:
        tool_errors.append(event)

    async def on_policy_invalid(event: Event) -> None:
        invalid_policy_events.append(event)

    bus.subscribe("on_tool_error", on_tool_error)
    bus.subscribe("on_policy_invalid", on_policy_invalid)

    result = await manager.execute_tool(
        "subprocess_bound_tool",
        _request(request_id="req-reason-codes", policy={"max_retries": "bad-value"}),
    )

    assert result.success is False
    assert result.metadata["reason_code"] == "policy_invalid"
    assert result.metadata["error"]["code"] == "policy_invalid"
    assert invalid_policy_events
    assert invalid_policy_events[0].payload["reason_code"] == "policy_invalid"
    assert invalid_policy_events[0].payload["action"] == "deny"
    assert invalid_policy_events[0].payload["code"] == "policy_invalid"
    assert invalid_policy_events[0].payload["category"] == "policy"
    assert tool_errors
    assert tool_errors[0].payload["reason_code"] == "policy_invalid"
    assert tool_errors[0].payload["reason"] == "policy_invalid"
    assert tool_errors[0].payload["code"] == "policy_invalid"
    assert tool_errors[0].payload["category"] == "policy"
    assert tool_errors[0].payload["retryable"] is False
