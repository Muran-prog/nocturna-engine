"""AI DSL parsing and dry-run plan entrypoints."""

from __future__ import annotations

from typing import Any

from nocturna_engine.core.plugin_v2 import AIPlan, parse_ai_dsl

from .rejection import _PlanRejectionMixin


class _PlanDSLMixin(_PlanRejectionMixin):
    async def ai(self, dsl: str) -> dict[str, Any]:
        """AI-first short DSL entrypoint."""

        payload = parse_ai_dsl(dsl)
        target = payload.get("target", "")
        goal = payload.get("goal", "full")
        mode = payload.get("mode", "auto")
        safe = str(payload.get("safe", "")).lower() in {"1", "true", "yes"}
        return await self.ai_scan(target, goal=goal, mode=mode, safe=safe)

    def plan_ai(self, dsl_or_target: str, *, goal: str = "full", mode: str = "auto") -> AIPlan:
        """Build explainable plan without executing tools."""

        if "=" in dsl_or_target:
            return self.plugin_manager.plan_from_dsl(dsl_or_target)
        return self.plugin_manager.plan_capability_aware(
            target=dsl_or_target,
            goal=goal,
            mode=mode,
        )
