"""Legacy plugin execution flow."""

from __future__ import annotations

from datetime import UTC, datetime

from nocturna_engine.exceptions import PluginExecutionError
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, merge_retry_exceptions, retry_async, with_timeout
from nocturna_engine.core.plugin_manager.execution.isolation import execute_tool_isolated


class PluginLegacyExecutionMixin:
    """Legacy execution pathway for plugin manager."""

    async def _execute_tool_legacy(self, tool_name: str, request: ScanRequest) -> ScanResult:
        started_at = datetime.now(UTC)
        try:
            tool = await self._ensure_tool_instance(tool_name)
        except PluginExecutionError as exc:
            return self._build_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                error_message=str(exc),
            )
        if tool is None:
            setup_failure = self._get_tool_setup_failure(tool_name)
            if setup_failure is not None:
                error_details = dict(setup_failure["error_details"])
                await self._event_bus.publish(
                    "on_tool_error",
                    self._build_setup_error_event_payload(
                        tool_name=tool_name,
                        setup_failure=setup_failure,
                        request_id=request.request_id,
                    ),
                )
                return self._build_failure_result_for_reason(
                    request=request,
                    tool_name=tool_name,
                    started_at=started_at,
                    error_message=str(setup_failure["error"]),
                    reason=str(setup_failure["reason"]),
                    reason_code=str(setup_failure["reason_code"]),
                    metadata={"stage": "setup"},
                    error_details=error_details,
                )

            return self._build_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                error_message=f"Tool '{tool_name}' is unavailable.",
            )

        dispatch_failure = await self._validate_dispatch_constraints(
            tool_name=tool_name,
            tool=tool,
            request=request,
            started_at=started_at,
        )
        if dispatch_failure is not None:
            return dispatch_failure

        await self._event_bus.publish(
            "on_tool_started",
            {"tool": tool_name, "request_id": request.request_id},
        )

        timeout_seconds = float(getattr(tool, "timeout_seconds", self._default_timeout_seconds))
        retries = int(min(getattr(tool, "max_retries", request.retries), request.retries))

        if getattr(tool, 'isolated', False):
            result = await execute_tool_isolated(type(tool), request, timeout_seconds)
            self._finalize_result_timing(result=result, started_at=started_at)
            if result.success:
                for finding in result.findings:
                    await self._event_bus.publish(
                        "on_raw_finding_detected",
                        {
                            "tool": tool_name,
                            "request_id": request.request_id,
                            "severity": finding.severity.value,
                            "finding_id": finding.finding_id,
                            "finding_fingerprint": finding.fingerprint,
                        },
                    )
            else:
                await self._event_bus.publish(
                    "on_tool_error",
                    {"tool": tool_name, "request_id": request.request_id, "error": result.error_message},
                )
            await self._event_bus.publish(
                "on_tool_finished",
                {
                    "tool": tool_name,
                    "request_id": request.request_id,
                    "success": result.success,
                    "duration_ms": result.duration_ms,
                },
            )
            return result


        effective_retry_exceptions = merge_retry_exceptions(
            getattr(tool, 'retry_exceptions', ()),
        )

        try:

            async def _execute() -> ScanResult:
                return await with_timeout(
                    tool.execute(request),
                    timeout_seconds=timeout_seconds,
                    operation_name=f"tool_execute:{tool_name}",
                )

            result = await retry_async(
                _execute,
                retries=retries,
                retry_exceptions=effective_retry_exceptions,
            )
            if not result.findings:

                async def _parse() -> list[Finding]:
                    return await with_timeout(
                        tool.parse_output(result.raw_output, request),
                        timeout_seconds=timeout_seconds,
                        operation_name=f"tool_parse:{tool_name}",
                    )

                parsed = await retry_async(
                    _parse,
                    retries=retries,
                    retry_exceptions=effective_retry_exceptions,
                )
                result.findings = parsed
            result.request_id = request.request_id
            result.tool_name = tool_name
            result.success = result.success and result.error_message is None
        except Exception as exc:
            result = self._build_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                error_message=str(exc),
            )
            await self._event_bus.publish(
                "on_tool_error",
                {"tool": tool_name, "request_id": request.request_id, "error": str(exc)},
            )
            self._logger.warning("tool_execution_failed", tool=tool_name, error=str(exc))

        self._finalize_result_timing(result=result, started_at=started_at)

        if result.success:
            for finding in result.findings:
                await self._event_bus.publish(
                    "on_raw_finding_detected",
                    {
                        "tool": tool_name,
                        "request_id": request.request_id,
                        "severity": finding.severity.value,
                        "finding_id": finding.finding_id,
                        "finding_fingerprint": finding.fingerprint,
                    },
                )

        await self._event_bus.publish(
            "on_tool_finished",
            {
                "tool": tool_name,
                "request_id": request.request_id,
                "success": result.success,
                "duration_ms": result.duration_ms,
            },
        )
        return result
