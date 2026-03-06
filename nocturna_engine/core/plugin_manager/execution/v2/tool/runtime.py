"""Runtime stage for v2 single-tool execution."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nocturna_engine.exceptions import NocturnaError, error_details_from_exception
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, merge_retry_exceptions, retry_async, with_timeout

from .models import ToolPreflightState


async def run_tool_runtime(
    manager: Any,
    *,
    tool_name: str,
    request: ScanRequest,
    started_at: datetime,
    preflight: ToolPreflightState,
) -> ScanResult:
    """Run tool adapter with resolved runtime policy and limits."""
    timeout_seconds, retries, max_output_bytes = manager._resolve_runtime_limits(
        request=request,
        adapter=preflight.adapter,
        policy_decision=preflight.policy_decision,
        default_timeout_seconds=manager._default_timeout_seconds,
    )
    # TODO: Add process-level isolation support for v2 adapters.
    # When the adapter's underlying BaseTool has `isolated=True`, route through
    # `execute_tool_isolated()` from `...isolation`.  Requires inspecting the
    # adapter to find the concrete BaseTool class (adapter._tool or similar).

    context = manager.build_runtime_context(request=request, policy=preflight.policy)
    context.policy = {
        **dict(context.policy),
        "effective_timeout_seconds": timeout_seconds,
        "effective_retries": retries,
        "effective_max_output_bytes": max_output_bytes,
    }

    await manager._event_bus.publish(
        "on_tool_started",
        {
            "tool": tool_name,
            "request_id": request.request_id,
            "effective_timeout_seconds": timeout_seconds,
            "effective_retries": retries,
            "effective_max_output_bytes": max_output_bytes,
        },
    )

    if preflight.policy.strict_quarantine:
        breaker_threshold = min(
            preflight.policy.circuit_breaker_threshold,
            preflight.registration.manifest.health_profile.failure_threshold,
        )
    else:
        breaker_threshold = max(
            preflight.policy.circuit_breaker_threshold,
            preflight.registration.manifest.health_profile.failure_threshold,
        )
    breaker_quarantine_seconds = max(
        preflight.policy.quarantine_seconds,
        preflight.registration.manifest.health_profile.quarantine_seconds,
    )

    tool_retry_exceptions = getattr(preflight.adapter, 'retry_exceptions', ())
    if not tool_retry_exceptions:
        tool_retry_exceptions = getattr(
            getattr(preflight.adapter, '_tool', None), 'retry_exceptions', ()
        )
    effective_retry_exceptions = merge_retry_exceptions(tool_retry_exceptions)

    try:

        async def _execute() -> ScanResult:
            return await with_timeout(
                preflight.adapter.execute(request, context),
                timeout_seconds=timeout_seconds,
                operation_name=f"tool_execute:{tool_name}",
            )

        result = await retry_async(
            _execute,
            retries=retries,
            retry_exceptions=effective_retry_exceptions,
        )
        result.request_id = request.request_id
        result.tool_name = tool_name
        result.success = result.success and result.error_message is None
        result.metadata = {
            **result.metadata,
            "manifest_id": preflight.registration.manifest.id,
            "manifest_version": preflight.registration.manifest.version,
            "cache_hit": False,
            "policy_applied": preflight.policy.model_dump(mode="json"),
            "effective_timeout_seconds": timeout_seconds,
            "effective_retries": retries,
            "effective_max_output_bytes": max_output_bytes,
        }

        manager._enforce_output_limit(
            result=result,
            tool_name=tool_name,
            max_output_bytes=max_output_bytes,
        )

        if result.success:
            manager._circuit_breaker.record_success(tool_name)
            if preflight.cache_key is not None:
                await manager._result_cache.set(preflight.cache_key, result)
        else:
            reason = result.metadata.get("reason")
            reason_code = result.metadata.get("reason_code")
            if not isinstance(reason, str) or not reason:
                reason = "execution_soft_failure"
            if not isinstance(reason_code, str) or not reason_code:
                reason_code = "execution_soft_failure"

            error_message = result.error_message or reason
            error_details = manager._normalize_existing_error_details(
                result.metadata.get("error"),
                fallback_reason_code=reason_code,
                stage="execution",
                context={"tool": tool_name},
            )

            quarantined = False
            if reason_code != "output_limit_exceeded":
                quarantined = manager._circuit_breaker.record_failure(
                    tool_name,
                    threshold=breaker_threshold,
                    quarantine_seconds=breaker_quarantine_seconds,
                    error_message=error_message,
                )

            error_details = manager._merge_error_context(
                error_details,
                context={"quarantined": quarantined},
            )
            result.metadata = manager._with_error_metadata(
                metadata={**result.metadata, "quarantined": quarantined},
                reason=reason,
                reason_code=reason_code,
                error_details=error_details,
            )

            await manager._publish_tool_error_event(
                tool_name=tool_name,
                request=request,
                error=error_message,
                stage="execution",
                reason=reason,
                reason_code=reason_code,
                extra={"quarantined": quarantined},
                error_details=error_details,
            )
            manager._logger.warning(
                "tool_execution_soft_failed",
                tool=tool_name,
                error=error_message,
            )
    except Exception as exc:
        reason_code = "execution_error"
        if isinstance(exc, NocturnaError) and exc.code:
            reason_code = str(exc.code)
        reason = reason_code
        quarantined = manager._circuit_breaker.record_failure(
            tool_name,
            threshold=breaker_threshold,
            quarantine_seconds=breaker_quarantine_seconds,
            error_message=str(exc),
        )
        error_details = error_details_from_exception(
            exc,
            default_code=reason_code,
            default_category=manager._error_category_for_stage("execution"),
            default_retryable=False,
            default_remediation="Inspect tool runtime logs and plugin implementation.",
            context={"tool": tool_name, "quarantined": quarantined},
        )
        result = manager._build_failure_result_for_reason(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=str(exc),
            reason=reason,
            reason_code=reason_code,
            metadata={
                "quarantined": quarantined,
                "effective_timeout_seconds": timeout_seconds,
                "effective_retries": retries,
                "effective_max_output_bytes": max_output_bytes,
            },
            error=exc,
            error_details=error_details,
        )
        await manager._publish_tool_error_event(
            tool_name=tool_name,
            request=request,
            error=str(exc),
            stage="execution",
            reason=reason,
            reason_code=reason_code,
            extra={"quarantined": quarantined},
            error_details=error_details,
        )
        manager._logger.warning("tool_execution_failed", tool=tool_name, error=str(exc))

    return result
