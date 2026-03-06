"""AI-first scan entrypoint requiring minimal manual configuration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from nocturna_engine.models.scan_request import ScanRequest

from .dsl import _PlanDSLMixin


class _EngineAIPlanningMixin(_PlanDSLMixin):
    async def ai_scan(
        self,
        target: str,
        *,
        goal: str = "full",
        mode: str = "auto",
        safe: bool | None = None,
    ) -> dict[str, Any]:
        """AI-first scan entrypoint requiring minimal manual configuration."""

        if not self.plugin_manager.list_registered_tools():
            pass  # No built-in plugins; register tools before calling ai_scan.

        request_id = str(uuid4())
        normalized_target = target.strip()
        policy_payload = self._policy_from_safe_flag(safe)
        policy_result = self.plugin_manager.build_policy_result(
            policy_payload,
            fail_closed=True,
        )
        plan = self.plugin_manager.plan_capability_aware(
            target=target,
            goal=goal,
            mode=mode,
            policy_payload=policy_payload,
            fail_closed=True,
        )

        if not policy_result.valid:
            await self._reject_ai_plan(
                request_id=request_id,
                target=normalized_target,
                goal=goal,
                mode=mode,
                safe=safe,
                plan=plan,
                policy_payload=policy_payload,
                reason="AI policy payload is invalid.",
                reason_code="ai_policy_invalid",
                remediation="Fix AI policy payload schema and retry.",
                policy_error=policy_result.error,
                publish_policy_invalid=True,
            )

        selected_tools = plan.selected_tools()
        if not selected_tools:
            await self._reject_ai_plan(
                request_id=request_id,
                target=normalized_target,
                goal=goal,
                mode=mode,
                safe=safe,
                plan=plan,
                policy_payload=policy_payload,
                reason="AI plan resolved no runnable tools.",
                reason_code="ai_plan_all_skipped" if plan.skipped else "ai_plan_empty",
                remediation="Adjust target/goal/mode/policy or register compatible tools.",
            )

        policy_denied: dict[str, str] = {}
        runnable_tools: list[str] = []
        descriptions = self.plugin_manager.describe_all_tools(machine_readable=True)
        for tool_name in selected_tools:
            descriptor = descriptions.get(tool_name)
            if not isinstance(descriptor, Mapping):
                policy_denied[tool_name] = "tool_manifest_unavailable"
                continue
            try:
                decision = self.plugin_manager.evaluate_manifest_payload(
                    descriptor,
                    policy_result.policy,
                )
            except Exception as exc:
                policy_denied[tool_name] = f"policy_evaluation_error:{exc}"
                continue
            if decision.allowed:
                runnable_tools.append(tool_name)
            else:
                policy_denied[tool_name] = str(decision.reason or decision.reason_code or "policy_denied")

        if not runnable_tools:
            rejected_plan = self._with_plan_skips(plan, policy_denied)
            await self._reject_ai_plan(
                request_id=request_id,
                target=normalized_target,
                goal=goal,
                mode=mode,
                safe=safe,
                plan=rejected_plan,
                policy_payload=policy_payload,
                reason="AI policy rejected all selected tools.",
                reason_code="ai_no_runnable_tools",
                remediation="Adjust policy permissions or select compatible AI tools.",
                extra_context={
                    "selected_tools": list(selected_tools),
                    "policy_denied_tools": dict(policy_denied),
                },
            )

        if policy_denied:
            plan = self._filter_plan_to_runnable(
                plan,
                runnable_tools=runnable_tools,
                policy_denied=policy_denied,
            )

        request = ScanRequest(
            request_id=request_id,
            targets=[self._build_target_from_ai_input(target)],
            tool_names=runnable_tools,
            options={},
            timeout_seconds=float(self._config.get("engine", {}).get("default_timeout_seconds", 60.0)),
            concurrency_limit=int(self._config.get("engine", {}).get("max_concurrency", 4)),
            metadata={
                "ai_goal": goal,
                "ai_mode": mode,
                "policy": policy_payload,
                "speed": "safe" if safe else "fast",
                "ai_fail_closed": True,
                "ai_plan": plan.as_dict(),
                "ai_plan_explain": plan.explain(),
            },
        )
        context = await self.run_scan(request)
        context["ai_plan"] = plan.as_dict()
        context["ai_plan_explain"] = plan.explain()
        return context
