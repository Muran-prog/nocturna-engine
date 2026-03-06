"""Batch execution flow for plugin system v2."""

from __future__ import annotations

from datetime import UTC, datetime

from nocturna_engine.core.plugin_v2 import POLICY_REASON_INVALID, PluginHealthStatus
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class PluginV2BatchExecutionMixin:
    """Batch v2 execution and preflight orchestration for plugin manager."""

    async def _execute_all_v2(self, *, request: ScanRequest, selected: list[str]) -> list[ScanResult]:
        ai_fail_closed = self._is_ai_fail_closed_request(request)
        ai_plan_payload = request.metadata.get("ai_plan")
        plan_context = dict(ai_plan_payload) if isinstance(ai_plan_payload, dict) else None
        plan_explain_raw = request.metadata.get("ai_plan_explain")
        plan_explain = plan_explain_raw if isinstance(plan_explain_raw, str) and plan_explain_raw else None

        async def _deny_for_invalid_policy(
            *,
            reason: str,
            reason_code: str,
            policy_error: str | None,
        ) -> list[ScanResult]:
            reason_text = reason_code if ai_fail_closed else reason
            error_context: dict[str, object] = {
                "action": "deny",
                "tools": list(selected),
            }
            if plan_context is not None:
                error_context["plan"] = dict(plan_context)

            error_details = self._runtime_error_details(
                reason_code=reason_code,
                stage="policy",
                remediation="Fix policy payload schema and retry.",
                context=error_context,
            )
            await self._publish_policy_invalid_event(
                request=request,
                reason=reason,
                reason_code=reason_code,
                policy_error=policy_error,
                error_details=error_details,
                action="deny",
                tools=list(selected),
            )
            if ai_fail_closed:
                await self._publish_ai_plan_rejected_event(
                    request=request,
                    reason=reason_text,
                    reason_code=reason_code,
                    error_details=error_details,
                    plan=plan_context,
                    plan_explain=plan_explain,
                    extra={
                        "policy_error": policy_error,
                        "tools": list(selected),
                    },
                )

            denied_results: dict[str, ScanResult] = {}
            for tool_name in selected:
                await self._publish_tool_error_event(
                    tool_name=tool_name,
                    request=request,
                    error=reason_text,
                    stage="policy",
                    reason=reason_text,
                    reason_code=reason_code,
                    extra={"policy_error": policy_error},
                    error_details=error_details,
                )
                denied_results[tool_name] = self._build_failure_result_for_reason(
                    request=request,
                    tool_name=tool_name,
                    started_at=datetime.now(UTC),
                    error_message=reason_text,
                    reason=reason_text,
                    reason_code=reason_code,
                    metadata={"policy_error": policy_error},
                    error_details=error_details,
                )
            return [denied_results[name] for name in selected]

        policy_result = self._resolve_policy_result(
            request=request,
            for_v2_execution=True,
        )
        if not policy_result.valid:
            reason = policy_result.reason or POLICY_REASON_INVALID
            reason_code = "ai_policy_invalid" if ai_fail_closed else (policy_result.reason_code or POLICY_REASON_INVALID)
            return await _deny_for_invalid_policy(
                reason=reason,
                reason_code=reason_code,
                policy_error=policy_result.error,
            )

        policy = policy_result.policy
        if policy_result.reason_code == POLICY_REASON_INVALID:
            if ai_fail_closed:
                reason = policy_result.reason or POLICY_REASON_INVALID
                reason_code = "ai_policy_invalid"
                return await _deny_for_invalid_policy(
                    reason=reason,
                    reason_code=reason_code,
                    policy_error=policy_result.error,
                )

            reason = policy_result.reason or POLICY_REASON_INVALID
            reason_code = policy_result.reason_code or POLICY_REASON_INVALID
            error_details = self._runtime_error_details(
                reason_code=reason_code,
                stage="policy",
                remediation="Policy payload invalid; default policy fallback applied.",
                context={"action": "fallback", "tools": list(selected)},
            )
            await self._publish_policy_invalid_event(
                request=request,
                reason=reason,
                reason_code=reason_code,
                policy_error=policy_result.error,
                error_details=error_details,
                action="fallback",
                tools=list(selected),
            )

        context = self.build_runtime_context(request=request, policy=policy)
        health = await self._health_orchestrator.run(
            tool_names=selected,
            adapter_resolver=self.resolve_tool_adapter,
            context=context,
            concurrency_limit=min(self._max_concurrency, request.concurrency_limit),
        )

        runnable = [name for name in selected if health.get(name, PluginHealthStatus(name, False)).healthy]
        skipped = [name for name in selected if name not in runnable]

        adaptive_concurrency = self._resolve_adaptive_concurrency(
            selected=selected,
            runnable=runnable,
            request=request,
        )

        run_results = await self._execute_with_backpressure(
            request=request,
            tool_names=runnable,
            concurrency_limit=adaptive_concurrency,
        )
        run_by_name = {result.tool_name: result for result in run_results}

        skipped_results: dict[str, ScanResult] = {}
        for tool_name in skipped:
            status = health.get(tool_name)
            reason = "preflight_failed"
            if status is not None and status.reason:
                reason = status.reason
            error_details = self._runtime_error_details(
                reason_code=reason,
                stage="preflight",
                remediation="Inspect preflight health checks and plugin dependencies.",
                context={"tool": tool_name},
            )
            skipped_results[tool_name] = self._build_failure_result_for_reason(
                request=request,
                tool_name=tool_name,
                started_at=datetime.now(UTC),
                error_message=f"Preflight skipped: {reason}",
                reason=reason,
                reason_code=reason,
                metadata={"skip_reason": reason},
                error_details=error_details,
            )

        return [
            run_by_name.get(name) or skipped_results[name]
            for name in selected
        ]
