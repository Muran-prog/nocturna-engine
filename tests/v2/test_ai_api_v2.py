"""Tests for AI-first engine APIs in plugin platform v2."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import pytest

from nocturna_engine.core.engine import NocturnaEngine
from nocturna_engine.core.event_bus import Event, EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.core.plugin_v2 import AIPlan, PlanStep
from nocturna_engine.exceptions import ValidationError
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class StaticConfigService:
    """Simple config service fake with v2 feature flags enabled."""

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


class AiReconTool(BaseTool):
    """Deterministic tool for AI API smoke tests."""

    name: ClassVar[str] = "ai_recon_tool"
    supported_phases: ClassVar[tuple[str, ...]] = ("recon",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("domain",)
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "recon", "category": "external", "tags": ("web",), "coverage_hint": 0.8, "cost_hint": 0.5},
    )

    async def execute(self, request: ScanRequest) -> ScanResult:
        target = request.targets[0].domain or "unknown"
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"target": target},
            findings=[
                Finding(
                    title="AI recon finding",
                    description="Synthetic finding",
                    severity=SeverityLevel.INFO,
                    tool=self.name,
                    target=target,
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


class AiNeverRunTool(BaseTool):
    """Tool used to verify AI fail-closed behavior for empty plans."""

    name: ClassVar[str] = "ai_never_run_tool"
    calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        _ = request
        AiNeverRunTool.calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"calls": AiNeverRunTool.calls},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


class AiPolicyDeniedTool(BaseTool):
    """Tool used to test policy-based AI rejections before execution."""

    name: ClassVar[str] = "ai_policy_denied_tool"
    requires_network: ClassVar[bool] = True
    calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        _ = request
        AiPolicyDeniedTool.calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"calls": AiPolicyDeniedTool.calls},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []


@pytest.mark.asyncio()
async def test_ai_scan_runs_with_one_liner_api() -> None:
    engine = NocturnaEngine(config_service=StaticConfigService())
    engine.register_tool(AiReconTool)

    async with engine:
        context = await engine.ai_scan("example.com")

    assert "scan_results" in context
    assert "ai_plan" in context
    assert "ai_plan_explain" in context
    assert len(context["scan_results"]) >= 1


@pytest.mark.asyncio()
async def test_ai_scan_rejects_empty_plan_without_executing_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = NocturnaEngine(config_service=StaticConfigService())
    engine.register_tool(AiNeverRunTool)
    AiNeverRunTool.calls = 0

    empty_plan = AIPlan(
        target="example.com",
        goal="recon",
        mode="auto",
        steps=[],
        skipped={},
    )
    monkeypatch.setattr(engine.plugin_manager, "plan_capability_aware", lambda **_: empty_plan)

    async with engine:
        with pytest.raises(ValidationError) as exc_info:
            await engine.ai_scan("example.com", goal="recon")

    assert exc_info.value.code == "ai_plan_empty"
    assert exc_info.value.context["plan"]["steps"] == []
    assert AiNeverRunTool.calls == 0


@pytest.mark.asyncio()
async def test_ai_scan_fails_closed_when_plan_has_no_runnable_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = NocturnaEngine(config_service=StaticConfigService())
    engine.register_tool(AiNeverRunTool)
    AiNeverRunTool.calls = 0

    empty_plan = AIPlan(
        target="example.com",
        goal="recon",
        mode="auto",
        steps=[],
        skipped={"ai_never_run_tool": "insufficient_relevance"},
    )
    monkeypatch.setattr(engine.plugin_manager, "plan_capability_aware", lambda **_: empty_plan)

    async with engine:
        with pytest.raises(ValidationError) as exc_info:
            await engine.ai_scan("example.com", goal="recon")

    assert exc_info.value.code == "ai_plan_all_skipped"
    assert AiNeverRunTool.calls == 0


@pytest.mark.asyncio()
async def test_ai_scan_rejects_invalid_policy_payload_with_events(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = NocturnaEngine(config_service=StaticConfigService())
    engine.register_tool(AiNeverRunTool)
    AiNeverRunTool.calls = 0

    policy_invalid_events: list[Event] = []
    rejected_events: list[Event] = []

    async def on_policy_invalid(event: Event) -> None:
        policy_invalid_events.append(event)

    async def on_ai_plan_rejected(event: Event) -> None:
        rejected_events.append(event)

    engine.subscribe("on_policy_invalid", on_policy_invalid)
    engine.subscribe("on_ai_plan_rejected", on_ai_plan_rejected)
    monkeypatch.setattr(
        NocturnaEngine,
        "_policy_from_safe_flag",
        staticmethod(lambda _safe: {"max_retries": "invalid"}),
    )

    async with engine:
        with pytest.raises(ValidationError) as exc_info:
            await engine.ai_scan("example.com", goal="recon")

    assert exc_info.value.code == "ai_policy_invalid"
    assert exc_info.value.context["reason_code"] == "ai_policy_invalid"
    assert exc_info.value.context["plan"]["target"] == "example.com"
    assert policy_invalid_events
    assert policy_invalid_events[0].payload["reason_code"] == "ai_policy_invalid"
    assert policy_invalid_events[0].payload["action"] == "deny"
    assert "plan" in policy_invalid_events[0].payload
    assert rejected_events
    assert rejected_events[0].payload["reason_code"] == "ai_policy_invalid"
    assert "plan_explain" in rejected_events[0].payload
    assert AiNeverRunTool.calls == 0


@pytest.mark.asyncio()
async def test_ai_scan_rejects_when_policy_forbids_all_selected_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = NocturnaEngine(config_service=StaticConfigService())
    engine.register_tool(AiPolicyDeniedTool)
    AiPolicyDeniedTool.calls = 0

    forced_plan = AIPlan(
        target="example.com",
        goal="recon",
        mode="auto",
        steps=[PlanStep(tool_name="ai_policy_denied_tool", score=1.0)],
        skipped={},
    )
    monkeypatch.setattr(engine.plugin_manager, "plan_capability_aware", lambda **_: forced_plan)

    async with engine:
        with pytest.raises(ValidationError) as exc_info:
            await engine.ai_scan("example.com", goal="recon", safe=True)

    assert exc_info.value.code == "ai_no_runnable_tools"
    assert exc_info.value.context["policy_denied_tools"]["ai_policy_denied_tool"] == "policy_denied:network"
    assert AiPolicyDeniedTool.calls == 0


@pytest.mark.asyncio()
async def test_v2_ai_fail_closed_denies_invalid_policy_without_fallback() -> None:
    AiNeverRunTool.calls = 0
    bus = EventBus()
    manager = PluginManager(event_bus=bus)
    manager.apply_runtime_config(
        {
            "features": {
                "plugin_system_v2": True,
                "policy_fail_closed": False,
            }
        }
    )
    manager.register_tool_class(AiNeverRunTool)

    policy_invalid_events: list[Event] = []
    rejected_events: list[Event] = []

    async def on_policy_invalid(event: Event) -> None:
        policy_invalid_events.append(event)

    async def on_ai_plan_rejected(event: Event) -> None:
        rejected_events.append(event)

    bus.subscribe("on_policy_invalid", on_policy_invalid)
    bus.subscribe("on_ai_plan_rejected", on_ai_plan_rejected)

    request = ScanRequest(
        request_id="ai-v2-invalid-policy",
        targets=[Target(domain="example.com")],
        tool_names=["ai_never_run_tool"],
        metadata={
            "ai_fail_closed": True,
            "policy": {"max_retries": "bad"},
            "ai_plan": {
                "target": "example.com",
                "goal": "recon",
                "mode": "auto",
                "steps": [
                    {
                        "tool_name": "ai_never_run_tool",
                        "score": 1.0,
                        "reasons": ["forced"],
                        "fallback_tools": [],
                        "estimated_cost": 1.0,
                    }
                ],
                "skipped": {},
            },
        },
    )

    results = await manager.execute_all(request=request)

    assert len(results) == 1
    assert results[0].success is False
    assert results[0].metadata["reason_code"] == "ai_policy_invalid"
    assert policy_invalid_events
    assert policy_invalid_events[0].payload["reason_code"] == "ai_policy_invalid"
    assert policy_invalid_events[0].payload["action"] == "deny"
    assert rejected_events
    assert rejected_events[0].payload["reason_code"] == "ai_policy_invalid"
    assert AiNeverRunTool.calls == 0


@pytest.mark.asyncio()
async def test_v2_ai_fail_closed_does_not_fallback_to_all_registered_tools() -> None:
    AiNeverRunTool.calls = 0
    manager = PluginManager(event_bus=EventBus())
    manager.apply_runtime_config({"features": {"plugin_system_v2": True}})
    manager.register_tool_class(AiNeverRunTool)

    request = ScanRequest(
        request_id="ai-v2-empty-selection",
        targets=[Target(domain="example.com")],
        metadata={
            "ai_fail_closed": True,
            "ai_plan": {
                "target": "example.com",
                "goal": "recon",
                "mode": "auto",
                "steps": [],
                "skipped": {},
            },
        },
    )

    with pytest.raises(ValidationError) as exc_info:
        await manager.execute_all(request=request)

    assert exc_info.value.code == "ai_plan_empty"
    assert exc_info.value.context["plan"]["steps"] == []
    assert AiNeverRunTool.calls == 0


@pytest.mark.parametrize(
    ("raw_target",),
    [
        ("foo/bar",),
        ("C:/tmp/x",),
        ("C:\\tmp\\x",),
        ("\\\\server\\share\\x",),
    ],
    ids=["relative_path", "windows_drive_path", "windows_backslash_path", "windows_unc_path"],
)
def test_build_target_from_ai_input_path_like_targets_resolve_to_local_scan(raw_target: str) -> None:
    target = NocturnaEngine._build_target_from_ai_input(raw_target)

    assert target.domain == "local.scan"
    assert target.metadata["target_path"] == str(Path(raw_target).expanduser().resolve(strict=False))


@pytest.mark.parametrize(
    ("raw_target", "expected_domain"),
    [
        ("example.com/path", "example.com"),
        ("example.com", "example.com"),
    ],
    ids=["domain_with_path", "plain_domain"],
)
def test_build_target_from_ai_input_keeps_domain_precedence(raw_target: str, expected_domain: str) -> None:
    target = NocturnaEngine._build_target_from_ai_input(raw_target)

    assert target.domain == expected_domain
    assert target.metadata.get("target_path") is None


def test_build_target_from_ai_input_prefers_domain_before_existing_local_path() -> None:
    domain_like_filename = "example.com"
    domain_like_file = Path(domain_like_filename)
    domain_like_file.write_text("placeholder", encoding="utf-8")

    try:
        target = NocturnaEngine._build_target_from_ai_input(domain_like_filename)
    finally:
        domain_like_file.unlink(missing_ok=True)

    assert target.domain == domain_like_filename
    assert target.metadata.get("target_path") is None


@pytest.mark.asyncio()
async def test_ai_dsl_and_plan_api_return_explainable_outputs() -> None:
    engine = NocturnaEngine(config_service=StaticConfigService())
    engine.register_tool(AiReconTool)

    async with engine:
        context = await engine.ai("target=example.com goal=recon speed=fast safe=true")
        plan = engine.plan_ai("target=example.com goal=recon")

    assert context["ai_plan"]["steps"]
    assert "reasons" in context["ai_plan"]["steps"][0]
    assert "AI plan for target=example.com" in plan.explain()
    assert engine.plugins.describe("ai_recon_tool", include_schema=True) is not None
    assert "ai_recon_tool" in engine.plugins.describe_all(machine_readable=True)
