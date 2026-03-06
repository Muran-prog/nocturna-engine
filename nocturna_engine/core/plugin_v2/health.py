"""Preflight health-check orchestration for plugin execution planning."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from nocturna_engine.utils.async_helpers import bounded_gather, with_timeout

from .contracts import PluginRuntimeContext


@dataclass(slots=True, frozen=True)
class PluginHealthStatus:
    """Health-check result for one plugin."""

    plugin_name: str
    healthy: bool
    reason: str | None = None
    latency_ms: int = 0


class PreflightHealthOrchestrator:
    """Runs fast health checks and explains skipped plugins."""

    def __init__(self, logger: Any, *, default_timeout_seconds: float = 2.0) -> None:
        self._logger = logger
        self._default_timeout_seconds = default_timeout_seconds

    async def run(
        self,
        *,
        tool_names: list[str],
        adapter_resolver: Any,
        context: PluginRuntimeContext,
        concurrency_limit: int,
    ) -> dict[str, PluginHealthStatus]:
        """Execute health checks with bounded concurrency."""

        async def _build_op(tool_name: str) -> PluginHealthStatus:
            started = time.monotonic()
            try:
                adapter = await adapter_resolver(tool_name)
                if adapter is None:
                    return PluginHealthStatus(
                        plugin_name=tool_name,
                        healthy=False,
                        reason="unavailable",
                    )
                manifest = getattr(adapter, "manifest", None)
                timeout_seconds = self._default_timeout_seconds
                if manifest is not None:
                    timeout_seconds = float(manifest.health_profile.check_timeout_seconds)
                healthy = await with_timeout(
                    adapter.health_check(context),
                    timeout_seconds=timeout_seconds,
                    operation_name=f"preflight_health:{tool_name}",
                )
                elapsed = int(max(0.0, (time.monotonic() - started) * 1000))
                if not healthy:
                    return PluginHealthStatus(
                        plugin_name=tool_name,
                        healthy=False,
                        reason="health_check_failed",
                        latency_ms=elapsed,
                    )
                return PluginHealthStatus(
                    plugin_name=tool_name,
                    healthy=True,
                    latency_ms=elapsed,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                elapsed = int(max(0.0, (time.monotonic() - started) * 1000))
                self._logger.warning(
                    "preflight_health_failed",
                    tool=tool_name,
                    error=str(exc),
                )
                return PluginHealthStatus(
                    plugin_name=tool_name,
                    healthy=False,
                    reason=str(exc),
                    latency_ms=elapsed,
                )

        factories = [lambda tool_name=name: _build_op(tool_name) for name in tool_names]
        results = await bounded_gather(
            factories,
            concurrency_limit=max(1, concurrency_limit),
            return_exceptions=True,
        )
        normalized: dict[str, PluginHealthStatus] = {}
        for tool_name, item in zip(tool_names, results):
            if isinstance(item, BaseException):
                normalized[tool_name] = PluginHealthStatus(
                    plugin_name=tool_name,
                    healthy=False,
                    reason=str(item),
                )
            else:
                normalized[tool_name] = item
        return normalized

