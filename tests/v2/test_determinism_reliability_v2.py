"""Determinism and reliability regression tests for plugin runtime v2."""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import sys
import types
from typing import Any, ClassVar
from uuid import uuid4

import pytest

from nocturna_engine.core.engine import NocturnaEngine
from nocturna_engine.core.event_bus import Event, EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


def _request(
    *,
    request_id: str,
    tool_names: list[str] | None = None,
    policy: dict[str, Any] | None = None,
) -> ScanRequest:
    metadata: dict[str, Any] = {}
    if policy is not None:
        metadata["policy"] = policy
    return ScanRequest(
        request_id=request_id,
        targets=[Target(domain="example.com")],
        tool_names=tool_names,
        metadata=metadata,
    )


class RaceInitTool(BaseTool):
    name: ClassVar[str] = "race_init_tool"
    setup_calls: ClassVar[int] = 0
    execute_calls: ClassVar[int] = 0
    setup_started: ClassVar[asyncio.Event | None] = None
    setup_release: ClassVar[asyncio.Event | None] = None

    async def setup(self) -> None:
        RaceInitTool.setup_calls += 1
        if RaceInitTool.setup_started is not None:
            RaceInitTool.setup_started.set()
        if RaceInitTool.setup_release is not None:
            await RaceInitTool.setup_release.wait()
        await super().setup()

    async def execute(self, request: ScanRequest) -> ScanResult:
        RaceInitTool.execute_calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"ok": True},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []


class SoftFailureTool(BaseTool):
    name: ClassVar[str] = "soft_failure_tool"
    execute_calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        SoftFailureTool.execute_calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            success=False,
            error_message="soft-failure",
            metadata={"reason": "soft_failure"},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []


class DiscoveryNoiseTool(BaseTool):
    name: ClassVar[str] = "discovery_noise_tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []


class NoHealthCheckTool(BaseTool):
    name: ClassVar[str] = "no_health_check_tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Any]:
        _ = raw_output
        _ = request
        return []


class CountingConfigService:
    def __init__(self) -> None:
        self.load_calls = 0

    def load(self) -> dict[str, Any]:
        self.load_calls += 1
        return {
            "engine": {"max_concurrency": 4, "default_timeout_seconds": 30.0},
            "plugins": {"auto_discover_packages": []},
            "features": {},
        }

    def get(self, key: str, default: Any = None) -> Any:
        _ = key
        return default


class GatedPluginManager(PluginManager):
    def __init__(self, *, event_bus: EventBus) -> None:
        super().__init__(event_bus=event_bus)
        self.initialize_calls = 0
        self.initialize_started = asyncio.Event()
        self.initialize_release = asyncio.Event()

    async def initialize_plugins(self) -> None:
        self.initialize_calls += 1
        self.initialize_started.set()
        await self.initialize_release.wait()
        await super().initialize_plugins()


def _v2_manager(*, event_bus: EventBus | None = None) -> PluginManager:
    manager = PluginManager(event_bus=event_bus or EventBus())
    manager.apply_runtime_config({"features": {"plugin_system_v2": True}})
    return manager


@pytest.mark.asyncio()
async def test_event_bridge_wildcard_receives_one_event_per_publish() -> None:
    bus = EventBus(enable_v2_bridge=True)
    received: list[Event] = []

    async def wildcard(event: Event) -> None:
        received.append(event)

    bus.subscribe("*", wildcard)
    await bus.publish("on_tool_started", {"request_id": "req-bridge-1"})
    await bus.publish("tool.started", {"request_id": "req-bridge-2"})

    assert [event.name for event in received] == ["on_tool_started", "tool.started"]


@pytest.mark.asyncio()
async def test_concurrent_tool_initialization_runs_setup_once() -> None:
    RaceInitTool.setup_calls = 0
    RaceInitTool.execute_calls = 0
    RaceInitTool.setup_started = asyncio.Event()
    RaceInitTool.setup_release = asyncio.Event()

    manager = PluginManager(event_bus=EventBus())
    manager.register_tool_class(RaceInitTool)
    request = _request(request_id="req-race-init", tool_names=["race_init_tool"])

    first = asyncio.create_task(manager.execute_tool("race_init_tool", request))
    await RaceInitTool.setup_started.wait()
    second = asyncio.create_task(manager.execute_tool("race_init_tool", request))
    await asyncio.sleep(0)
    RaceInitTool.setup_release.set()

    try:
        results = await asyncio.gather(first, second)
    finally:
        RaceInitTool.setup_started = None
        RaceInitTool.setup_release = None

    assert all(item.success for item in results)
    assert RaceInitTool.setup_calls == 1
    assert RaceInitTool.execute_calls == 2


@pytest.mark.asyncio()
async def test_concurrent_engine_start_runs_initialization_once() -> None:
    bus = EventBus()
    manager = GatedPluginManager(event_bus=bus)
    config = CountingConfigService()
    engine = NocturnaEngine(
        plugin_manager=manager,
        event_bus=bus,
        config_service=config,
    )

    first = asyncio.create_task(engine.start())
    await manager.initialize_started.wait()
    second = asyncio.create_task(engine.start())
    await asyncio.sleep(0)
    manager.initialize_release.set()

    await asyncio.gather(first, second)
    assert manager.initialize_calls == 1
    assert config.load_calls == 1
    await engine.stop()


@pytest.mark.asyncio()
async def test_soft_failure_trips_circuit_breaker_and_quarantine() -> None:
    SoftFailureTool.execute_calls = 0
    manager = _v2_manager()
    manager.register_tool_class(SoftFailureTool)

    policy = {
        "circuit_breaker_threshold": 1,
        "quarantine_seconds": 120.0,
        "strict_quarantine": True,
    }
    first = await manager.execute_tool(
        "soft_failure_tool",
        _request(request_id="req-soft-1", policy=policy),
    )
    second = await manager.execute_tool(
        "soft_failure_tool",
        _request(request_id="req-soft-2", policy=policy),
    )

    assert first.success is False
    assert second.success is False
    assert second.metadata["reason_code"] == "tool_quarantined"
    assert SoftFailureTool.execute_calls == 1


@pytest.mark.asyncio()
async def test_preflight_health_check_skips_heavy_setup_when_not_required() -> None:
    manager = _v2_manager()
    manager.register_tool_class(NoHealthCheckTool)

    status = await manager.preflight_health_check(
        request=_request(request_id="req-preflight"),
        tool_names=["no_health_check_tool"],
    )

    assert status["no_health_check_tool"]["healthy"] is True
    assert status["no_health_check_tool"]["reason"] == "preflight_skipped_no_startup_check"


def test_discovery_is_deterministic_by_default_for_package_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    package_name = f"deterministic_pkg_{uuid4().hex[:8]}"
    module_name = f"{package_name}.sample_plugin"
    plugin_name = "deterministic_pkg_tool"

    package_module = types.ModuleType(package_name)
    package_module.__path__ = [package_name]
    plugin_module = types.ModuleType(module_name)

    class DeterministicPkgTool(BaseTool):
        name = plugin_name

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
        ) -> list[Any]:
            _ = raw_output
            _ = request
            return []

    DeterministicPkgTool.__module__ = module_name
    setattr(plugin_module, "DeterministicPkgTool", DeterministicPkgTool)

    monkeypatch.setitem(sys.modules, package_name, package_module)
    monkeypatch.setitem(sys.modules, module_name, plugin_module)

    def _walk_packages(path: Any, prefix: str = "") -> list[tuple[None, str, bool]]:
        _ = path
        if prefix == f"{package_name}.":
            return [(None, module_name, False)]
        return []

    monkeypatch.setattr(pkgutil, "walk_packages", _walk_packages)
    importlib.invalidate_caches()

    manager = PluginManager(event_bus=EventBus())
    discovered = manager.discover_plugins(package_name)

    assert plugin_name in discovered
    assert "discovery_noise_tool" not in discovered
    description = manager.describe_tool(plugin_name)
    assert description is not None
    assert description["implementation"]["source"] == "discovery"
