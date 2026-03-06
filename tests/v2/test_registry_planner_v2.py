"""Tests for deterministic registry and capability-aware planner in plugin v2."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class ReconTool(BaseTool):
    """Tool with explicit recon/web capabilities."""

    name: ClassVar[str] = "recon_tool"
    version: ClassVar[str] = "2.1.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("recon",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("domain",)
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "web", "category": "recon", "tags": ("external", "dns"), "coverage_hint": 0.8, "cost_hint": 0.7},
    )

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


class CodeTool(BaseTool):
    """Tool optimized for source-code targets."""

    name: ClassVar[str] = "code_tool"
    version: ClassVar[str] = "1.4.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("scanning",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("directory", "source_code")
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "sast", "category": "code", "tags": ("semgrep",), "coverage_hint": 0.9, "cost_hint": 1.1},
    )

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


class InfraTool(BaseTool):
    """Tool optimized for network/IP scope targets."""

    name: ClassVar[str] = "infra_tool"
    version: ClassVar[str] = "1.0.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("recon",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("ip", "cidr")
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "infra", "category": "recon", "tags": ("network",), "coverage_hint": 0.7, "cost_hint": 0.8},
    )

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


class UrlTool(BaseTool):
    """Tool optimized for URL/web targets."""

    name: ClassVar[str] = "url_tool"
    version: ClassVar[str] = "1.0.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("recon",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("url",)
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "web", "category": "recon", "tags": ("url",), "coverage_hint": 0.8, "cost_hint": 0.6},
    )

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


def _sample_request() -> ScanRequest:
    return ScanRequest(targets=[Target(domain="example.com")])


def _manager() -> PluginManager:
    manager = PluginManager(event_bus=EventBus())
    manager.apply_runtime_config({"features": {"plugin_system_v2": True, "ai_api_v2": True}})
    return manager


def test_deterministic_registry_exposes_machine_readable_manifest() -> None:
    manager = _manager()
    manager.register_tool_class(ReconTool)

    description = manager.describe_tool("recon_tool", include_schema=True)

    assert description is not None
    assert description["id"] == "recon_tool"
    assert description["version"] == "2.1.0"
    assert description["supported_targets"] == ["domain"]
    assert description["implementation"]["legacy_adapter_required"] is True


def test_capability_aware_planner_prioritizes_goal_and_target_match() -> None:
    manager = _manager()
    manager.register_tool_class(ReconTool)
    manager.register_tool_class(CodeTool)

    plan = manager.plan_capability_aware(
        target="example.com",
        goal="web recon external",
        mode="auto",
    )

    assert plan.steps
    assert plan.steps[0].tool_name == "recon_tool"
    assert "code_tool" in plan.skipped or any(step.tool_name == "code_tool" for step in plan.steps)
    assert "recon_tool" in plan.explain()


def test_planner_infers_windows_path_target_type_for_code_tools() -> None:
    manager = _manager()
    manager.register_tool_class(ReconTool)
    manager.register_tool_class(CodeTool)

    plan = manager.plan_capability_aware(
        target=r"C:\\workspace\\repo\\src\\",
        goal="scanning sast",
        mode="auto",
    )

    assert plan.steps
    assert plan.steps[0].tool_name == "code_tool"


def test_planner_infers_url_ip_and_cidr_targets() -> None:
    manager = _manager()
    manager.register_tool_class(ReconTool)
    manager.register_tool_class(InfraTool)
    manager.register_tool_class(UrlTool)

    url_plan = manager.plan_capability_aware(
        target="https://example.com/login",
        goal="web recon",
        mode="auto",
    )
    ip_plan = manager.plan_capability_aware(
        target="192.168.10.11",
        goal="network recon",
        mode="auto",
    )
    cidr_plan = manager.plan_capability_aware(
        target="10.0.0.0/24",
        goal="network recon",
        mode="auto",
    )

    assert url_plan.steps[0].tool_name == "url_tool"
    assert ip_plan.steps[0].tool_name == "infra_tool"
    assert cidr_plan.steps[0].tool_name == "infra_tool"
