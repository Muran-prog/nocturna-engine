"""Batch dispatch helpers for core execution."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.utils.async_helpers import bounded_gather


class PluginExecutionBatchMixin:
    async def execute_tool(self, tool_name: str, request: ScanRequest) -> ScanResult:
        """Execute one plugin against a scan request."""

        if self.is_feature_enabled("plugin_system_v2"):
            return await self._execute_tool_v2(tool_name, request)
        return await self._execute_tool_legacy(tool_name, request)

    async def execute_all(self, request: ScanRequest, tool_names: list[str] | None = None) -> list[ScanResult]:
        """Execute many plugins with bounded concurrency."""

        explicit_selection = tool_names if tool_names is not None else request.tool_names
        if explicit_selection is None and self._is_ai_fail_closed_request(request):
            raise self._build_ai_selection_validation_error(
                request=request,
                reason_code="ai_plan_empty",
                remediation="Provide a non-empty AI plan with explicit runnable tools.",
            )

        selected = explicit_selection if explicit_selection is not None else self.list_registered_tools()
        selected = [name for name in selected if name in self._registry]
        if not selected:
            if self._is_ai_fail_closed_request(request):
                reason_code = "ai_no_runnable_tools" if explicit_selection else "ai_plan_empty"
                remediation = (
                    "Ensure AI plan tools are registered and allowed by active policy."
                    if explicit_selection
                    else "Provide a non-empty AI plan with explicit runnable tools."
                )
                raise self._build_ai_selection_validation_error(
                    request=request,
                    reason_code=reason_code,
                    remediation=remediation,
                )
            return []

        if self.is_feature_enabled("plugin_system_v2"):
            return await self._execute_all_v2(request=request, selected=selected)

        factories = [self._build_executor(tool_name=name, request=request) for name in selected]
        results = await bounded_gather(
            factories,
            concurrency_limit=min(self._max_concurrency, request.concurrency_limit),
            return_exceptions=True,
        )

        normalized: list[ScanResult] = []
        for tool_name, item in zip(selected, results):
            if isinstance(item, BaseException):
                normalized.append(
                    self._build_failure_result(
                        request=request,
                        tool_name=tool_name,
                        started_at=datetime.now(UTC),
                        error_message=str(item),
                    )
                )
                await self._event_bus.publish(
                    "on_tool_error",
                    {"tool": tool_name, "request_id": request.request_id, "error": str(item)},
                )
            else:
                normalized.append(item)
        return normalized

    def _build_executor(self, tool_name: str, request: ScanRequest) -> Callable[[], Awaitable[ScanResult]]:
        """Create one deferred tool execution operation."""

        async def _execute() -> ScanResult:
            return await self.execute_tool(tool_name, request)

        return _execute

