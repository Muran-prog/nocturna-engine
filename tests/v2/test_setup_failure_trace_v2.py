"""Tests for setup-failure diagnostics propagation in plugin manager v2."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class FlakySetupV2Tool(BaseTool):
    """Tool that fails setup until toggled off."""

    name: ClassVar[str] = "flaky_setup_v2_tool"
    max_retries: ClassVar[int] = 0
    fail_setup: ClassVar[bool] = True
    setup_calls: ClassVar[int] = 0

    async def setup(self) -> None:
        FlakySetupV2Tool.setup_calls += 1
        if FlakySetupV2Tool.fail_setup:
            raise RuntimeError("v2 setup boom")
        await super().setup()

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


def _manager(*, event_bus: EventBus | None = None) -> PluginManager:
    manager = PluginManager(event_bus=event_bus or EventBus())
    manager.apply_runtime_config({"features": {"plugin_system_v2": True}})
    return manager


def _request(request_id: str) -> ScanRequest:
    return ScanRequest(
        request_id=request_id,
        targets=[Target(domain="example.com")],
    )


@pytest.mark.asyncio()
async def test_v2_setup_exception_surfaces_root_cause_in_result_and_events() -> None:
    FlakySetupV2Tool.fail_setup = True
    FlakySetupV2Tool.setup_calls = 0

    bus = EventBus()
    manager = _manager(event_bus=bus)
    manager.register_tool_class(FlakySetupV2Tool)

    tool_errors: list[dict[str, Any]] = []

    async def on_tool_error(event: Any) -> None:
        tool_errors.append(dict(event.payload))

    bus.subscribe("on_tool_error", on_tool_error)
    request = _request("req-v2-setup-fail")

    result = await manager.execute_tool("flaky_setup_v2_tool", request)

    assert result.success is False
    assert result.error_message == "v2 setup boom"
    assert result.metadata["reason"] == "tool_setup_failed"
    assert result.metadata["reason_code"] == "tool_setup_failed"
    assert result.metadata["stage"] == "setup"
    assert result.metadata["error"]["code"] == "tool_setup_failed"
    assert result.metadata["error"]["category"] == "plugin_setup"
    assert result.metadata["error"]["context"]["stage"] == "setup"
    assert result.metadata["error"]["context"]["tool"] == "flaky_setup_v2_tool"

    setup_events = [payload for payload in tool_errors if payload.get("stage") == "setup"]
    assert setup_events
    assert all(payload.get("reason") == "tool_setup_failed" for payload in setup_events)
    assert all(payload.get("reason_code") == "tool_setup_failed" for payload in setup_events)
    assert all("tool" in payload and "error" in payload and "stage" in payload for payload in setup_events)
    assert any(payload.get("request_id") == request.request_id for payload in setup_events)


@pytest.mark.asyncio()
async def test_v2_setup_failure_state_is_cleared_after_successful_retry() -> None:
    FlakySetupV2Tool.fail_setup = True
    FlakySetupV2Tool.setup_calls = 0

    manager = _manager()
    manager.register_tool_class(FlakySetupV2Tool)

    first = await manager.execute_tool("flaky_setup_v2_tool", _request("req-v2-setup-1"))
    assert first.success is False
    assert first.metadata["reason_code"] == "tool_setup_failed"

    FlakySetupV2Tool.fail_setup = False
    second = await manager.execute_tool("flaky_setup_v2_tool", _request("req-v2-setup-2"))

    assert second.success is True
    assert second.metadata.get("reason_code") != "tool_setup_failed"
    assert manager._tool_setup_failures.get("flaky_setup_v2_tool") is None
    assert FlakySetupV2Tool.setup_calls == 2
