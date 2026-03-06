"""Adapter resolution checks for preflight."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nocturna_engine.exceptions import PluginExecutionError, error_details_from_exception
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


async def resolve_preflight_adapter(
    manager: Any,
    *,
    tool_name: str,
    request: ScanRequest,
    started_at: datetime,
) -> tuple[Any | None, ScanResult | None]:
    """Resolve adapter and convert setup errors to early results."""
    try:
        adapter = await manager.resolve_tool_adapter(tool_name)
    except PluginExecutionError as exc:
        error_details = error_details_from_exception(
            exc,
            default_code="adapter_error",
            default_category=manager._error_category_for_stage("adapter"),
            default_retryable=False,
            default_remediation="Check plugin setup and runtime dependencies.",
            context={"tool": tool_name},
        )
        await manager._publish_tool_error_event(
            tool_name=tool_name,
            request=request,
            error=str(exc),
            stage="adapter",
            reason="adapter_error",
            reason_code="adapter_error",
            error_details=error_details,
        )
        return None, manager._build_failure_result_for_reason(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=str(exc),
            reason="adapter_error",
            reason_code="adapter_error",
            error=exc,
            error_details=error_details,
        )

    if adapter is None:
        setup_failure = manager._get_tool_setup_failure(tool_name)
        if setup_failure is not None:
            reason = str(setup_failure["reason"])
            reason_code = str(setup_failure["reason_code"])
            error_message = str(setup_failure["error"])
            error_details = manager._normalize_existing_error_details(
                setup_failure.get("error_details"),
                fallback_reason_code=reason_code,
                stage="setup",
                context={"tool": tool_name, "stage": "setup"},
            )
            await manager._publish_tool_error_event(
                tool_name=tool_name,
                request=request,
                error=error_message,
                stage="setup",
                reason=reason,
                reason_code=reason_code,
                error_details=error_details,
            )
            return None, manager._build_failure_result_for_reason(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                error_message=error_message,
                reason=reason,
                reason_code=reason_code,
                metadata={"stage": "setup"},
                error_details=error_details,
            )

        reason = "tool_unavailable"
        error_message = f"Tool '{tool_name}' is unavailable."
        error_details = manager._runtime_error_details(
            reason_code=reason,
            stage="adapter",
            remediation="Register the plugin before execution.",
            context={"tool": tool_name},
        )
        await manager._publish_tool_error_event(
            tool_name=tool_name,
            request=request,
            error=error_message,
            stage="adapter",
            reason=reason,
            reason_code=reason,
            error_details=error_details,
        )
        return None, manager._build_failure_result_for_reason(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=error_message,
            reason=reason,
            reason_code=reason,
            error_details=error_details,
        )

    return adapter, None

