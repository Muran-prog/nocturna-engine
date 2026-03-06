"""AI plan rejection and error enrichment logic."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.core.plugin_v2 import AIPlan
from nocturna_engine.exceptions import ValidationError, build_error_details

from .filters import _PlanFiltersMixin


class _PlanRejectionMixin(_PlanFiltersMixin):
    async def _reject_ai_plan(
        self,
        *,
        request_id: str,
        target: str,
        goal: str,
        mode: str,
        safe: bool | None,
        plan: AIPlan,
        policy_payload: Mapping[str, Any],
        reason: str,
        reason_code: str,
        remediation: str,
        policy_error: str | None = None,
        publish_policy_invalid: bool = False,
        extra_context: Mapping[str, Any] | None = None,
    ) -> None:
        plan_payload = plan.as_dict()
        context: dict[str, Any] = {
            "request_id": request_id,
            "target": target,
            "goal": goal,
            "mode": mode,
            "reason_code": reason_code,
            "plan": plan_payload,
            "skipped": dict(plan.skipped),
        }
        if extra_context is not None:
            context.update({str(key): value for key, value in extra_context.items()})
        if policy_error is not None:
            context["policy_error"] = policy_error

        error_details = build_error_details(
            code=reason_code,
            category="planning",
            retryable=False,
            remediation=remediation,
            context=context,
        )

        base_payload: dict[str, Any] = {
            "request_id": request_id,
            "target": target,
            "goal": goal,
            "mode": mode,
            "safe": safe,
            "reason": reason,
            "reason_code": reason_code,
            "policy": dict(policy_payload),
            "plan": plan_payload,
            "plan_explain": plan.explain(),
        }
        if policy_error is not None:
            base_payload["policy_error"] = policy_error
        payload = self._with_ai_error_fields(base_payload, error_details)

        if publish_policy_invalid:
            policy_payload_event = dict(payload)
            policy_payload_event.update(
                {
                    "error": policy_error,
                    "action": "deny",
                    "tools": plan.selected_tools(),
                }
            )
            await self.event_bus.publish("on_policy_invalid", policy_payload_event)

        await self.event_bus.publish("on_ai_plan_rejected", payload)

        raise ValidationError(
            reason,
            code=reason_code,
            category="planning",
            remediation=remediation,
            context=dict(error_details["context"]),
        )

    @staticmethod
    def _with_ai_error_fields(payload: Mapping[str, Any], error_details: Mapping[str, Any]) -> dict[str, Any]:
        enriched = dict(payload)
        enriched["error_details"] = dict(error_details)
        enriched["code"] = error_details["code"]
        enriched["category"] = error_details["category"]
        enriched["retryable"] = bool(error_details.get("retryable", False))
        enriched["remediation"] = error_details.get("remediation")
        context_payload = error_details.get("context")
        enriched["context"] = dict(context_payload) if isinstance(context_payload, Mapping) else {}
        return enriched
