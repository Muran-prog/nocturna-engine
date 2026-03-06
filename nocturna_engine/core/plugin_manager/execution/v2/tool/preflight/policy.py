"""Policy resolution stage for preflight."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nocturna_engine.core.plugin_v2 import POLICY_REASON_INVALID
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


async def resolve_preflight_policy(
    manager: Any,
    *,
    tool_name: str,
    request: ScanRequest,
    started_at: datetime,
    registration: Any,
) -> tuple[Any | None, Any | None, ScanResult | None]:
    """Resolve and validate policy state for tool execution."""
    ai_fail_closed = manager._is_ai_fail_closed_request(request)
    ai_plan_payload = request.metadata.get("ai_plan")
    plan_context = dict(ai_plan_payload) if isinstance(ai_plan_payload, dict) else None
    plan_explain_raw = request.metadata.get("ai_plan_explain")
    plan_explain = plan_explain_raw if isinstance(plan_explain_raw, str) and plan_explain_raw else None

    policy_result = manager._resolve_policy_result(
        request=request,
        for_v2_execution=True,
    )
    if not policy_result.valid:
        policy_decision = manager._policy_engine.invalid_policy_decision()
        reason = policy_decision.reason or POLICY_REASON_INVALID
        reason_code = "ai_policy_invalid" if ai_fail_closed else (policy_decision.reason_code or POLICY_REASON_INVALID)
        reason_text = reason_code if ai_fail_closed else reason
        error_context: dict[str, Any] = {"tool": tool_name, "action": "deny"}
        if plan_context is not None:
            error_context["plan"] = dict(plan_context)
        error_details = manager._runtime_error_details(
            reason_code=reason_code,
            stage="policy",
            remediation="Fix policy payload schema and retry.",
            context=error_context,
        )
        await manager._publish_policy_invalid_event(
            request=request,
            reason=reason,
            reason_code=reason_code,
            policy_error=policy_result.error,
            error_details=error_details,
            action="deny",
            tool_name=tool_name,
        )
        if ai_fail_closed:
            await manager._publish_ai_plan_rejected_event(
                request=request,
                reason=reason_text,
                reason_code=reason_code,
                error_details=error_details,
                plan=plan_context,
                plan_explain=plan_explain,
                extra={
                    "policy_error": policy_result.error,
                    "tool": tool_name,
                },
            )
        await manager._publish_tool_error_event(
            tool_name=tool_name,
            request=request,
            error=reason_text,
            stage="policy",
            reason=reason_text,
            reason_code=reason_code,
            extra={"policy_error": policy_result.error},
            error_details=error_details,
        )
        return None, None, manager._build_failure_result_for_reason(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=reason_text,
            reason=reason_text,
            reason_code=reason_code,
            metadata={"policy_error": policy_result.error},
            error_details=error_details,
        )

    policy = policy_result.policy
    if policy_result.reason_code == POLICY_REASON_INVALID:
        if ai_fail_closed:
            reason = policy_result.reason or POLICY_REASON_INVALID
            reason_code = "ai_policy_invalid"
            error_context: dict[str, Any] = {"tool": tool_name, "action": "deny"}
            if plan_context is not None:
                error_context["plan"] = dict(plan_context)
            error_details = manager._runtime_error_details(
                reason_code=reason_code,
                stage="policy",
                remediation="Fix policy payload schema and retry.",
                context=error_context,
            )
            await manager._publish_policy_invalid_event(
                request=request,
                reason=reason,
                reason_code=reason_code,
                policy_error=policy_result.error,
                error_details=error_details,
                action="deny",
                tool_name=tool_name,
            )
            await manager._publish_ai_plan_rejected_event(
                request=request,
                reason=reason_code,
                reason_code=reason_code,
                error_details=error_details,
                plan=plan_context,
                plan_explain=plan_explain,
                extra={
                    "policy_error": policy_result.error,
                    "tool": tool_name,
                },
            )
            await manager._publish_tool_error_event(
                tool_name=tool_name,
                request=request,
                error=reason_code,
                stage="policy",
                reason=reason_code,
                reason_code=reason_code,
                extra={"policy_error": policy_result.error},
                error_details=error_details,
            )
            return None, None, manager._build_failure_result_for_reason(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                error_message=reason_code,
                reason=reason_code,
                reason_code=reason_code,
                metadata={"policy_error": policy_result.error},
                error_details=error_details,
            )

        reason = policy_result.reason or POLICY_REASON_INVALID
        reason_code = policy_result.reason_code or POLICY_REASON_INVALID
        error_details = manager._runtime_error_details(
            reason_code=reason_code,
            stage="policy",
            remediation="Policy payload invalid; default policy fallback applied.",
            context={"tool": tool_name, "action": "fallback"},
        )
        await manager._publish_policy_invalid_event(
            request=request,
            reason=reason,
            reason_code=reason_code,
            policy_error=policy_result.error,
            error_details=error_details,
            action="fallback",
            tool_name=tool_name,
        )

    policy_decision = manager._policy_engine.evaluate(registration.manifest, policy)
    if not policy_decision.allowed:
        reason = policy_decision.reason or "policy_denied"
        reason_code = policy_decision.reason_code or "policy_denied"
        error_details = manager._runtime_error_details(
            reason_code=reason_code,
            stage="policy",
            remediation="Adjust policy permissions or disable restricted plugin.",
            context={"tool": tool_name, "policy_reason": reason},
        )
        await manager._publish_tool_error_event(
            tool_name=tool_name,
            request=request,
            error=reason,
            stage="policy",
            reason=reason,
            reason_code=reason_code,
            error_details=error_details,
        )
        return None, None, manager._build_failure_result_for_reason(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=reason,
            reason=reason,
            reason_code=reason_code,
            error_details=error_details,
        )

    return policy, policy_decision, None
