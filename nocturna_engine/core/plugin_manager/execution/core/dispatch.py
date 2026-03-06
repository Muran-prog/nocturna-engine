"""Dispatch validation for core execution."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nocturna_engine.core.plugin_v2 import PluginPolicy
from nocturna_engine.core.security import SCOPE_REASON_DENIED
from nocturna_engine.exceptions import build_error_details
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class PluginDispatchValidationMixin:
    async def _validate_dispatch_constraints(
        self,
        *,
        tool_name: str,
        tool: Any,
        request: ScanRequest,
        started_at: datetime,
        policy: PluginPolicy | None = None,
    ) -> ScanResult | None:
        firewall = self._build_scope_firewall(request=request)
        for target in request.targets:
            decision = firewall.evaluate_target(target)
            if decision.allowed:
                continue
            target_value = str(decision.normalized_target or self._target_label(target))
            reason_text = str(decision.reason or decision.reason_code or SCOPE_REASON_DENIED)
            reason_code = str(decision.reason_code or SCOPE_REASON_DENIED)
            await self._event_bus.publish(
                "on_scope_denied",
                {
                    "request_id": request.request_id,
                    "tool": tool_name,
                    "target": target_value,
                    "reason": reason_text,
                    "reason_code": reason_code,
                },
            )
            return await self._build_dispatch_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                reason_code=reason_code,
                error_message=(
                    f"Scope firewall denied target '{target_value}' for tool '{tool_name}': {reason_text}."
                ),
                remediation=(
                    "Adjust security.scope_firewall allow/deny rules or disable kill-switch when authorized."
                ),
                context={
                    "tool": tool_name,
                    "target": target_value,
                    "reason": reason_text,
                    "firewall_reason_code": reason_code,
                },
            )

        unsupported_targets: list[str] = []
        for target in request.targets:
            try:
                if not bool(tool.supports_target(target)):
                    unsupported_targets.append(self._target_label(target))
            except Exception as exc:
                return await self._build_dispatch_failure_result(
                    request=request,
                    tool_name=tool_name,
                    started_at=started_at,
                    reason_code="unsupported_target",
                    error_message=(
                        f"Target compatibility check failed for tool '{tool_name}': {exc}"
                    ),
                    remediation="Fix tool supports_target implementation or adjust target input.",
                    context={
                        "tool": tool_name,
                        "target": self._target_label(target),
                    },
                )

        if unsupported_targets:
            return await self._build_dispatch_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                reason_code="unsupported_target",
                error_message=(
                    f"Tool '{tool_name}' does not support target(s): {', '.join(unsupported_targets)}."
                ),
                remediation="Choose a tool compatible with the target type.",
                context={
                    "tool": tool_name,
                    "unsupported_targets": unsupported_targets,
                },
            )

        out_of_scope: list[dict[str, Any]] = []
        for target in request.targets:
            if target.scope and not self._is_target_within_scope(target):
                out_of_scope.append(
                    {
                        "target": self._target_label(target),
                        "scope": list(target.scope),
                    }
                )
        if out_of_scope:
            out_of_scope_targets = [str(item["target"]) for item in out_of_scope]
            return await self._build_dispatch_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                reason_code="out_of_scope",
                error_message=(
                    f"Target(s) are out of scope for tool '{tool_name}': {', '.join(out_of_scope_targets)}."
                ),
                remediation="Adjust target values or extend scope allow-list entries.",
                context={
                    "tool": tool_name,
                    "out_of_scope": out_of_scope,
                },
            )

        egress_failure = await self._validate_subprocess_egress_preflight(
            tool_name=tool_name,
            tool=tool,
            request=request,
            started_at=started_at,
            policy=policy,
        )
        if egress_failure is not None:
            return egress_failure

        return None

    async def _build_dispatch_failure_result(
        self,
        *,
        request: ScanRequest,
        tool_name: str,
        started_at: datetime,
        reason_code: str,
        error_message: str,
        remediation: str,
        context: dict[str, Any],
    ) -> ScanResult:
        error_details = build_error_details(
            code=reason_code,
            category="validation",
            retryable=False,
            remediation=remediation,
            context=context,
        )
        await self._event_bus.publish(
            "on_tool_error",
            {
                "tool": tool_name,
                "request_id": request.request_id,
                "error": error_message,
                "stage": "dispatch",
                "reason": reason_code,
                "reason_code": reason_code,
                "code": error_details["code"],
                "category": error_details["category"],
                "retryable": error_details["retryable"],
                "remediation": error_details["remediation"],
                "context": dict(error_details["context"]),
            },
        )
        return self._build_failure_result_for_reason(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=error_message,
            reason=reason_code,
            reason_code=reason_code,
            metadata={"stage": "dispatch"},
            error_details=error_details,
        )

