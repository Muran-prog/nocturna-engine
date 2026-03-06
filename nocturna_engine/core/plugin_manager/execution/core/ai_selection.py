"""AI selection validation helpers for core execution."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.exceptions import ValidationError
from nocturna_engine.models.scan_request import ScanRequest


class PluginAISelectionMixin:
    def _build_ai_selection_validation_error(
        self,
        *,
        request: ScanRequest,
        reason_code: str,
        remediation: str,
    ) -> ValidationError:
        plan_context = self._build_ai_plan_context(request)
        return ValidationError(
            "AI execution rejected before dispatch.",
            code=reason_code,
            category="planning",
            remediation=remediation,
            context={
                "request_id": request.request_id,
                "reason_code": reason_code,
                "plan": plan_context,
            },
        )

    @classmethod
    def _build_ai_plan_context(cls, request: ScanRequest) -> dict[str, Any]:
        plan_payload = request.metadata.get("ai_plan")
        if isinstance(plan_payload, Mapping):
            return dict(plan_payload)
        target = cls._target_label(request.targets[0]) if request.targets else "unknown_target"
        return {
            "target": target,
            "goal": str(request.metadata.get("ai_goal", "full")),
            "mode": str(request.metadata.get("ai_mode", "auto")),
            "steps": [],
            "skipped": {},
        }

