"""Tool execution orchestrator for plugin system v2."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult

from .completion import publish_tool_completion
from .models import ToolPreflightState
from .preflight import run_tool_preflight
from .runtime import run_tool_runtime


class PluginV2ToolExecutionMixin:
    """Single-tool v2 execution for plugin manager."""

    async def _execute_tool_v2(self, tool_name: str, request: ScanRequest) -> ScanResult:
        started_at = datetime.now(UTC)
        registration = self._deterministic_registry.get_registration(tool_name)
        if registration is None:
            return await self._execute_tool_legacy(tool_name, request)

        preflight, early_result = await run_tool_preflight(
            self,
            tool_name=tool_name,
            request=request,
            started_at=started_at,
            registration=registration,
        )
        if early_result is not None:
            return early_result

        result = await run_tool_runtime(
            self,
            tool_name=tool_name,
            request=request,
            started_at=started_at,
            preflight=cast(ToolPreflightState, preflight),
        )

        self._finalize_result_timing(result=result, started_at=started_at)
        await publish_tool_completion(
            self,
            tool_name=tool_name,
            request=request,
            result=result,
        )
        return result
