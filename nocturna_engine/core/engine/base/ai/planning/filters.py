"""Static plan filtering and skip-merging helpers."""

from __future__ import annotations

from collections.abc import Mapping

from nocturna_engine.core.plugin_v2 import AIPlan

from ..targeting import _EngineAITargetingMixin


class _PlanFiltersMixin(_EngineAITargetingMixin):
    @staticmethod
    def _with_plan_skips(plan: AIPlan, skipped: Mapping[str, str]) -> AIPlan:
        merged_skipped = dict(plan.skipped)
        for tool_name, reason in skipped.items():
            merged_skipped[str(tool_name)] = str(reason)
        return AIPlan(
            target=plan.target,
            goal=plan.goal,
            mode=plan.mode,
            steps=list(plan.steps),
            skipped=merged_skipped,
        )

    @staticmethod
    def _filter_plan_to_runnable(
        plan: AIPlan,
        *,
        runnable_tools: list[str],
        policy_denied: Mapping[str, str],
    ) -> AIPlan:
        allowed = set(runnable_tools)
        filtered_steps = [step for step in plan.steps if step.tool_name in allowed]
        merged_skipped = dict(plan.skipped)
        for tool_name, reason in policy_denied.items():
            if tool_name not in allowed:
                merged_skipped[str(tool_name)] = str(reason)
        return AIPlan(
            target=plan.target,
            goal=plan.goal,
            mode=plan.mode,
            steps=filtered_steps,
            skipped=merged_skipped,
        )
