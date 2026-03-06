"""Event publishing helpers for plugin system v2 execution flow."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.models.scan_request import ScanRequest


class PluginV2EventPublishingMixin:
    """Error and policy event publishing helpers for plugin manager v2 flow."""

    async def _publish_tool_error_event(
        self,
        *,
        tool_name: str,
        request: ScanRequest,
        error: str,
        stage: str,
        reason: str,
        reason_code: str,
        extra: dict[str, Any] | None = None,
        error_details: Mapping[str, Any] | None = None,
    ) -> None:
        details = dict(
            error_details
            or self._runtime_error_details(
                reason_code=reason_code,
                stage=stage,
                context={"tool": tool_name, "stage": stage},
            )
        )
        payload: dict[str, Any] = self._with_error_fields(
            {
                "tool": tool_name,
                "request_id": request.request_id,
                "error": error,
                "stage": stage,
                "reason": reason,
                "reason_code": reason_code,
            },
            details,
        )
        if extra:
            payload.update(extra)
        await self._event_bus.publish("on_tool_error", payload)

    async def _publish_policy_invalid_event(
        self,
        *,
        request: ScanRequest,
        reason: str,
        reason_code: str,
        policy_error: str | None,
        error_details: Mapping[str, Any],
        action: str,
        tool_name: str | None = None,
        tools: list[str] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "request_id": request.request_id,
            "reason": reason,
            "reason_code": reason_code,
            "error": policy_error,
            "action": action,
        }
        if tool_name is not None:
            payload["tool"] = tool_name
        if tools is not None:
            payload["tools"] = list(tools)
        await self._event_bus.publish(
            "on_policy_invalid",
            self._with_error_fields(payload, error_details),
        )
        self._logger.warning(
            "policy_invalid_payload",
            request_id=request.request_id,
            reason=reason,
            reason_code=reason_code,
            action=action,
            tool=tool_name,
            tools=list(tools) if tools is not None else None,
            error=policy_error,
        )

    async def _publish_ai_plan_rejected_event(
        self,
        *,
        request: ScanRequest,
        reason: str,
        reason_code: str,
        error_details: Mapping[str, Any],
        plan: Mapping[str, Any] | None = None,
        plan_explain: str | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "request_id": request.request_id,
            "reason": reason,
            "reason_code": reason_code,
        }
        if plan is not None:
            payload["plan"] = dict(plan)
        if plan_explain:
            payload["plan_explain"] = plan_explain
        if extra:
            payload.update(dict(extra))
        await self._event_bus.publish(
            "on_ai_plan_rejected",
            self._with_error_fields(payload, error_details),
        )
        self._logger.warning(
            "ai_plan_rejected",
            request_id=request.request_id,
            reason=reason,
            reason_code=reason_code,
        )
