"""Edge-case tests for CapabilityAwarePlanner, AIPlan, DSL parsing, docs generation."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from nocturna_engine.core.plugin_v2.contracts import (
    CapabilityDescriptor,
    ExecutionRequirements,
    PluginManifest,
)
from nocturna_engine.core.plugin_v2.docs import generate_plugin_docs
from nocturna_engine.core.plugin_v2.health import PluginHealthStatus
from nocturna_engine.core.plugin_v2.planner.capability import CapabilityAwarePlanner
from nocturna_engine.core.plugin_v2.planner.dsl import parse_ai_dsl
from nocturna_engine.core.plugin_v2.planner.models import AIPlan, PlanStep
from nocturna_engine.core.plugin_v2.policy.engine import PluginPolicyEngine
from nocturna_engine.core.plugin_v2.policy.models import PluginPolicy
from nocturna_engine.core.plugin_v2.registry import build_manifest_from_tool_class
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


# ---------------------------------------------------------------------------
# Test doubles / helpers
# ---------------------------------------------------------------------------

class ReconTool(BaseTool):
    name: ClassVar[str] = "recon_tool"
    version: ClassVar[str] = "2.0.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("recon",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("domain",)
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "web", "category": "recon", "tags": ("external", "dns"), "coverage_hint": 0.8, "cost_hint": 0.7},
    )

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={})
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class ScannerTool(BaseTool):
    name: ClassVar[str] = "scanner_tool"
    version: ClassVar[str] = "1.0.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("scanning",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("domain", "url")
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "vuln_scan", "category": "scanning", "tags": ("nuclei",), "coverage_hint": 0.9, "cost_hint": 1.5},
    )

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={})
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class CodeTool(BaseTool):
    name: ClassVar[str] = "code_tool"
    version: ClassVar[str] = "1.4.0"
    supported_phases: ClassVar[tuple[str, ...]] = ("scanning",)
    supported_target_types: ClassVar[tuple[str, ...]] = ("directory", "source_code")
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "sast", "category": "code", "tags": ("semgrep",), "coverage_hint": 0.9, "cost_hint": 1.1},
    )

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={})
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class NetworkRequiringTool(BaseTool):
    name: ClassVar[str] = "netscan_tool"
    requires_network: ClassVar[bool] = True
    binary_name: ClassVar[str] = "nmap"
    supported_target_types: ClassVar[tuple[str, ...]] = ("ip", "cidr")
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "port_scan", "category": "recon", "tags": ("network",), "cost_hint": 2.0},
    )

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={})
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


def _build_descriptions(*tool_classes: type[BaseTool]) -> dict[str, dict[str, Any]]:
    """Build plugin_descriptions from tool classes."""
    result = {}
    for cls in tool_classes:
        manifest = build_manifest_from_tool_class(cls)
        payload = manifest.machine_readable(include_schema=False)
        result[manifest.id] = payload
    return result


def _planner() -> CapabilityAwarePlanner:
    return CapabilityAwarePlanner(policy_engine=PluginPolicyEngine())


# ---------------------------------------------------------------------------
# parse_ai_dsl
# ---------------------------------------------------------------------------

async def test_dsl_basic_parsing():
    payload = parse_ai_dsl("target=example.com goal=recon mode=auto")
    assert payload["target"] == "example.com"
    assert payload["goal"] == "recon"
    assert payload["mode"] == "auto"


async def test_dsl_empty_string():
    payload = parse_ai_dsl("")
    assert payload == {}


async def test_dsl_no_equals():
    payload = parse_ai_dsl("justwords no_equals_here")
    assert payload == {}


async def test_dsl_mixed_tokens():
    payload = parse_ai_dsl("target=host.com skip goal=full extra_word")
    assert payload["target"] == "host.com"
    assert payload["goal"] == "full"
    assert "skip" not in payload


async def test_dsl_quoted_values():
    payload = parse_ai_dsl('target="example.com" goal="web+recon"')
    assert payload["target"] == "example.com"
    assert payload["goal"] == "web+recon"


async def test_dsl_case_insensitive_keys():
    payload = parse_ai_dsl("TARGET=example.com GOAL=full")
    assert payload["target"] == "example.com"
    assert payload["goal"] == "full"


async def test_dsl_speed_and_safe():
    payload = parse_ai_dsl("target=host.com speed=fast safe=true")
    assert payload["speed"] == "fast"
    assert payload["safe"] == "true"


# ---------------------------------------------------------------------------
# AIPlan / PlanStep models
# ---------------------------------------------------------------------------

async def test_plan_step_defaults():
    step = PlanStep(tool_name="t", score=1.0)
    assert step.reasons == []
    assert step.fallback_tools == []
    assert step.estimated_cost == 1.0


async def test_plan_selected_tools():
    plan = AIPlan(
        target="t", goal="g", mode="m",
        steps=[PlanStep(tool_name="a", score=2.0), PlanStep(tool_name="b", score=1.0)],
    )
    assert plan.selected_tools() == ["a", "b"]


async def test_plan_selected_tools_empty():
    plan = AIPlan(target="t", goal="g", mode="m", steps=[])
    assert plan.selected_tools() == []


async def test_plan_explain():
    plan = AIPlan(
        target="example.com", goal="recon", mode="auto",
        steps=[PlanStep(tool_name="recon_tool", score=3.0, reasons=["matched recon"])],
        skipped={"bad_tool": "policy_denied"},
    )
    text = plan.explain()
    assert "example.com" in text
    assert "recon_tool" in text
    assert "matched recon" in text
    assert "bad_tool" in text
    assert "policy_denied" in text


async def test_plan_explain_empty():
    plan = AIPlan(target="t", goal="g", mode="m", steps=[])
    text = plan.explain()
    assert "target=t" in text


async def test_plan_as_dict():
    plan = AIPlan(
        target="t", goal="g", mode="m",
        steps=[PlanStep(tool_name="a", score=1.0, reasons=["r"])],
        skipped={"b": "reason"},
    )
    d = plan.as_dict()
    assert d["target"] == "t"
    assert len(d["steps"]) == 1
    assert d["steps"][0]["tool_name"] == "a"
    assert d["skipped"]["b"] == "reason"


async def test_plan_as_dict_empty():
    plan = AIPlan(target="t", goal="g", mode="m", steps=[])
    d = plan.as_dict()
    assert d["steps"] == []
    assert d["skipped"] == {}


# ---------------------------------------------------------------------------
# CapabilityAwarePlanner.plan()
# ---------------------------------------------------------------------------

async def test_planner_basic_plan():
    planner = _planner()
    descs = _build_descriptions(ReconTool, ScannerTool)
    plan = planner.plan(target="example.com", goal="recon", mode="auto", plugin_descriptions=descs)
    assert isinstance(plan, AIPlan)
    assert plan.target == "example.com"
    assert plan.goal == "recon"
    assert len(plan.steps) > 0


async def test_planner_target_type_matching():
    planner = _planner()
    descs = _build_descriptions(ReconTool, CodeTool)
    plan = planner.plan(target="example.com", goal="full", mode="auto", plugin_descriptions=descs)
    # ReconTool supports domain; CodeTool supports directory — domain target should favor recon
    tool_names = plan.selected_tools()
    if "recon_tool" in tool_names and "code_tool" in tool_names:
        # recon_tool should score higher due to target match
        idx_recon = tool_names.index("recon_tool")
        idx_code = tool_names.index("code_tool")
        assert idx_recon < idx_code


async def test_planner_directory_target():
    planner = _planner()
    descs = _build_descriptions(ReconTool, CodeTool)
    plan = planner.plan(target="./src", goal="sast", mode="auto", plugin_descriptions=descs)
    tool_names = plan.selected_tools()
    # CodeTool should appear since it supports directory
    assert "code_tool" in tool_names or len(plan.skipped) > 0


async def test_planner_ip_target():
    planner = _planner()
    descs = _build_descriptions(ReconTool, NetworkRequiringTool)
    plan = planner.plan(target="192.168.1.1", goal="recon", mode="auto", plugin_descriptions=descs)
    tool_names = plan.selected_tools()
    # NetworkRequiringTool supports ip
    assert "netscan_tool" in tool_names or "netscan_tool" in plan.skipped


async def test_planner_cidr_target():
    planner = _planner()
    descs = _build_descriptions(NetworkRequiringTool)
    plan = planner.plan(target="10.0.0.0/24", goal="recon", mode="auto", plugin_descriptions=descs)
    tool_names = plan.selected_tools()
    assert "netscan_tool" in tool_names or "netscan_tool" in plan.skipped


async def test_planner_url_target():
    planner = _planner()
    descs = _build_descriptions(ScannerTool, ReconTool)
    plan = planner.plan(target="https://example.com/app", goal="scanning", mode="auto", plugin_descriptions=descs)
    tool_names = plan.selected_tools()
    assert "scanner_tool" in tool_names


async def test_planner_empty_target():
    planner = _planner()
    descs = _build_descriptions(ReconTool)
    plan = planner.plan(target="", goal="full", mode="auto", plugin_descriptions=descs)
    assert isinstance(plan, AIPlan)


async def test_planner_empty_descriptions():
    planner = _planner()
    plan = planner.plan(target="example.com", goal="full", mode="auto", plugin_descriptions={})
    assert plan.steps == []
    assert plan.skipped == {}


async def test_planner_goal_overlap_scoring():
    planner = _planner()
    descs = _build_descriptions(ReconTool, ScannerTool)
    plan = planner.plan(target="example.com", goal="web+recon", mode="auto", plugin_descriptions=descs)
    # ReconTool should score well due to "web" and "recon" capability overlap
    if plan.steps:
        assert any("recon_tool" == s.tool_name for s in plan.steps)


async def test_planner_policy_denied_skipped():
    planner = _planner()
    descs = _build_descriptions(NetworkRequiringTool)
    policy = PluginPolicy(allow_network=False)
    plan = planner.plan(
        target="192.168.1.1", goal="recon", mode="auto",
        plugin_descriptions=descs, policy=policy,
    )
    assert "netscan_tool" in plan.skipped
    assert "policy_denied" in plan.skipped["netscan_tool"]


async def test_planner_unhealthy_tool_skipped():
    planner = _planner()
    descs = _build_descriptions(ReconTool)
    health = {"recon_tool": PluginHealthStatus(plugin_name="recon_tool", healthy=False, reason="health_failed")}
    plan = planner.plan(
        target="example.com", goal="recon", mode="auto",
        plugin_descriptions=descs, health_status=health,
    )
    assert "recon_tool" in plan.skipped


async def test_planner_max_steps():
    planner = _planner()
    descs = _build_descriptions(ReconTool, ScannerTool, CodeTool)
    plan = planner.plan(
        target="example.com", goal="full", mode="auto",
        plugin_descriptions=descs, max_steps=1,
    )
    assert len(plan.steps) <= 1


async def test_planner_max_steps_zero():
    planner = _planner()
    descs = _build_descriptions(ReconTool)
    plan = planner.plan(
        target="example.com", goal="full", mode="auto",
        plugin_descriptions=descs, max_steps=0,
    )
    # max_steps=0 means the guard `max_steps > 0` is False, so no truncation
    assert isinstance(plan.steps, list)


async def test_planner_fallback_tools():
    planner = _planner()
    descs = _build_descriptions(ReconTool, ScannerTool)
    plan = planner.plan(target="example.com", goal="recon+scanning", mode="auto", plugin_descriptions=descs)
    for step in plan.steps:
        # Fallback tools should not include self
        assert step.tool_name not in step.fallback_tools


async def test_planner_sorted_by_score():
    planner = _planner()
    descs = _build_descriptions(ReconTool, ScannerTool, CodeTool)
    plan = planner.plan(target="example.com", goal="full", mode="auto", plugin_descriptions=descs)
    for i in range(len(plan.steps) - 1):
        assert plan.steps[i].score >= plan.steps[i + 1].score


# ---------------------------------------------------------------------------
# _infer_target_type
# ---------------------------------------------------------------------------

async def test_infer_target_type_domain():
    assert CapabilityAwarePlanner._infer_target_type("example.com") == "domain"


async def test_infer_target_type_ip():
    assert CapabilityAwarePlanner._infer_target_type("192.168.1.1") == "ip"


async def test_infer_target_type_ipv6():
    assert CapabilityAwarePlanner._infer_target_type("[::1]") == "ip"


async def test_infer_target_type_cidr():
    assert CapabilityAwarePlanner._infer_target_type("10.0.0.0/8") == "cidr"


async def test_infer_target_type_url():
    assert CapabilityAwarePlanner._infer_target_type("https://example.com/path") == "url"


async def test_infer_target_type_empty():
    assert CapabilityAwarePlanner._infer_target_type("") == "domain"


async def test_infer_target_type_relative_path():
    assert CapabilityAwarePlanner._infer_target_type("./src") in {"directory", "file"}


async def test_infer_target_type_absolute_path():
    result = CapabilityAwarePlanner._infer_target_type("/usr/local/src")
    assert result in {"directory", "file"}


async def test_infer_target_type_domain_with_path():
    """example.com/path should be inferred as url because host part is a valid domain."""
    assert CapabilityAwarePlanner._infer_target_type("example.com/path") == "url"


# ---------------------------------------------------------------------------
# _tokenize
# ---------------------------------------------------------------------------

async def test_tokenize_basic():
    tokens = CapabilityAwarePlanner._tokenize("web+recon")
    assert "web" in tokens
    assert "recon" in tokens


async def test_tokenize_spaces():
    tokens = CapabilityAwarePlanner._tokenize("web recon scanning")
    assert len(tokens) == 3


async def test_tokenize_mixed_separators():
    tokens = CapabilityAwarePlanner._tokenize("web+recon,scanning;analysis full")
    assert "web" in tokens
    assert "recon" in tokens
    assert "scanning" in tokens
    assert "analysis" in tokens
    assert "full" in tokens


async def test_tokenize_empty():
    tokens = CapabilityAwarePlanner._tokenize("")
    assert tokens == set()


async def test_tokenize_case_insensitive():
    tokens = CapabilityAwarePlanner._tokenize("RECON+Web")
    assert "recon" in tokens
    assert "web" in tokens


# ---------------------------------------------------------------------------
# _target_match_candidates
# ---------------------------------------------------------------------------

async def test_target_match_candidates_domain():
    candidates = CapabilityAwarePlanner._target_match_candidates("domain")
    assert "domain" in candidates
    assert "fqdn" in candidates


async def test_target_match_candidates_unknown():
    candidates = CapabilityAwarePlanner._target_match_candidates("unknown_type")
    assert "unknown_type" in candidates


# ---------------------------------------------------------------------------
# generate_plugin_docs
# ---------------------------------------------------------------------------

async def test_generate_docs_basic():
    manifest = PluginManifest(
        id="test_tool", display_name="Test Tool", version="1.0",
        capabilities=(CapabilityDescriptor(name="scan", category="recon"),),
        supported_targets=("domain",),
    )
    docs = generate_plugin_docs(manifest)
    assert "manifest" in docs
    assert "human_markdown" in docs
    assert "Test Tool" in docs["human_markdown"]
    assert "scan" in docs["human_markdown"]


async def test_generate_docs_no_capabilities():
    manifest = PluginManifest(id="t", display_name="T", version="1.0")
    docs = generate_plugin_docs(manifest)
    assert "none" in docs["human_markdown"]


async def test_generate_docs_with_options_model():
    from pydantic import BaseModel

    class Options(BaseModel):
        threads: int = 4

    manifest = PluginManifest(id="t", display_name="T", version="1.0")
    docs = generate_plugin_docs(manifest, options_model=Options)
    assert docs["option_schema"] is not None
    assert "threads" in str(docs["option_schema"])


# ---------------------------------------------------------------------------
# PluginManager planning helpers
# ---------------------------------------------------------------------------

async def test_plan_capability_aware_basic():
    from nocturna_engine.core.plugin_manager import PluginManager
    pm = PluginManager()
    pm.register_tool_class(ReconTool)
    plan = pm.plan_capability_aware(target="example.com", goal="recon")
    assert isinstance(plan, AIPlan)
    assert plan.target == "example.com"


async def test_plan_capability_aware_invalid_policy_skips_all():
    from nocturna_engine.core.plugin_manager import PluginManager
    pm = PluginManager(feature_flags={"plugin_system_v2": True, "policy_fail_closed": True})
    pm.register_tool_class(ReconTool)
    plan = pm.plan_capability_aware(
        target="example.com", goal="recon",
        policy_payload={"max_timeout_seconds": -999},
    )
    assert plan.steps == []
    assert len(plan.skipped) > 0


async def test_plan_capability_aware_with_health_status():
    from nocturna_engine.core.plugin_manager import PluginManager
    pm = PluginManager()
    pm.register_tool_class(ReconTool)
    plan = pm.plan_capability_aware(
        target="example.com", goal="recon",
        health_status={"recon_tool": {"healthy": False, "reason": "down"}},
    )
    assert "recon_tool" in plan.skipped


async def test_plan_from_dsl():
    from nocturna_engine.core.plugin_manager import PluginManager
    pm = PluginManager()
    pm.register_tool_class(ReconTool)
    plan = pm.plan_from_dsl("target=example.com goal=recon mode=auto")
    assert plan.target == "example.com"
    assert plan.goal == "recon"


async def test_plan_from_dsl_safe_true():
    from nocturna_engine.core.plugin_manager import PluginManager
    pm = PluginManager()
    pm.register_tool_class(ReconTool)
    plan = pm.plan_from_dsl("target=example.com goal=full safe=true")
    # safe=true generates restrictive policy
    assert isinstance(plan, AIPlan)


async def test_plan_from_dsl_safe_false():
    from nocturna_engine.core.plugin_manager import PluginManager
    pm = PluginManager()
    pm.register_tool_class(ReconTool)
    plan = pm.plan_from_dsl("target=example.com goal=full safe=false")
    assert isinstance(plan, AIPlan)


async def test_plan_from_dsl_no_safe():
    from nocturna_engine.core.plugin_manager import PluginManager
    pm = PluginManager()
    pm.register_tool_class(ReconTool)
    plan = pm.plan_from_dsl("target=example.com goal=full")
    assert isinstance(plan, AIPlan)


async def test_extract_policy_from_dsl_safe_true():
    from nocturna_engine.core.plugin_manager.manager.planning import PluginManagerPlanningMixin
    result = PluginManagerPlanningMixin._extract_policy_from_dsl({"safe": "true"})
    assert result["allow_network"] is False
    assert result["default_egress_action"] == "deny"


async def test_extract_policy_from_dsl_safe_false():
    from nocturna_engine.core.plugin_manager.manager.planning import PluginManagerPlanningMixin
    result = PluginManagerPlanningMixin._extract_policy_from_dsl({"safe": "false"})
    assert result["allow_network"] is True
    assert result["default_egress_action"] == "allow"


async def test_extract_policy_from_dsl_no_safe():
    from nocturna_engine.core.plugin_manager.manager.planning import PluginManagerPlanningMixin
    result = PluginManagerPlanningMixin._extract_policy_from_dsl({})
    assert result == {}
