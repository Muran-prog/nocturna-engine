"""Plugin manager runtime context and health orchestration helpers."""

from __future__ import annotations

import asyncio
from typing import Any, Mapping

from nocturna_engine.core.plugin_v2 import (
    EnvironmentSecretAccessor,
    LegacyToolAdapter,
    POLICY_REASON_INVALID,
    PluginHealthStatus,
    PluginPolicy,
    PluginRuntimeContext,
)
from nocturna_engine.models.scan_request import ScanRequest


class PluginManagerRuntimeContextMixin:
    """Runtime context and adapter resolution operations for plugin manager."""

    def build_runtime_context(
        self,
        *,
        request: ScanRequest,
        policy: PluginPolicy | None = None,
    ) -> PluginRuntimeContext:
        """Build per-request v2 runtime context."""

        return PluginRuntimeContext(
            event_bus=self._event_bus,
            logger=self._logger.bind(request_id=request.request_id),
            config=self._config,
            secrets=EnvironmentSecretAccessor(
                source_name=f"plugin_manager:{request.request_id}",
                logger=self._logger,
            ),
            cache=self._runtime_cache,
            cancellation_token=asyncio.Event(),
            storage=self._storage,
            metrics=self._metrics,
            request_metadata=request.metadata,
            policy=(policy.model_dump(mode="python") if policy is not None else {}),
        )

    async def resolve_tool_adapter(self, tool_name: str) -> LegacyToolAdapter | None:
        """Resolve active plugin instance and wrap with v2 compatibility adapter."""

        tool = await self._ensure_tool_instance(tool_name)
        if tool is None:
            return None
        registration = self._deterministic_registry.get_registration(tool_name)
        if registration is None:
            return None
        return LegacyToolAdapter(
            tool_name=tool_name,
            tool=tool,
            manifest=registration.manifest,
        )

    async def resolve_tool_adapter_for_preflight(self, tool_name: str) -> LegacyToolAdapter | None:
        """Resolve lightweight adapter for preflight without forcing setup."""

        registration = self._deterministic_registry.get_registration(tool_name)
        if registration is None:
            return None

        tool = self._instances.get(tool_name)
        if tool is None:
            tool_class = self._registry.get(tool_name)
            if tool_class is None:
                return None
            try:
                tool = self._instantiate_tool(tool_class, tool_name)
            except Exception as exc:
                self._logger.warning(
                    "preflight_tool_instantiation_failed",
                    tool=tool_name,
                    error=str(exc),
                )
                return None
        return LegacyToolAdapter(
            tool_name=tool_name,
            tool=tool,
            manifest=registration.manifest,
        )

    async def preflight_health_check(
        self,
        *,
        request: ScanRequest,
        tool_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run fast plugin health checks and return explainable status map."""

        selected = tool_names or request.tool_names or self.list_registered_tools()
        selected = [name for name in selected if name in self._registry]
        policy_result = self._resolve_policy_result(request=request)
        if not policy_result.valid:
            reason = policy_result.reason or POLICY_REASON_INVALID
            reason_code = policy_result.reason_code or POLICY_REASON_INVALID
            await self._event_bus.publish(
                "on_policy_invalid",
                {
                    "request_id": request.request_id,
                    "reason": reason,
                    "reason_code": reason_code,
                    "error": policy_result.error,
                },
            )
            return {
                name: {
                    "healthy": False,
                    "reason": reason,
                    "latency_ms": 0,
                }
                for name in selected
            }
        policy = policy_result.policy
        context = self.build_runtime_context(request=request, policy=policy)
        skipped: dict[str, PluginHealthStatus] = {}
        runtime_checks: list[str] = []
        for name in selected:
            registration = self._deterministic_registry.get_registration(name)
            if registration is None:
                skipped[name] = PluginHealthStatus(
                    plugin_name=name,
                    healthy=False,
                    reason="preflight_skipped_unregistered",
                    latency_ms=0,
                )
                continue
            if not registration.manifest.health_profile.startup_check:
                skipped[name] = PluginHealthStatus(
                    plugin_name=name,
                    healthy=True,
                    reason="preflight_skipped_no_startup_check",
                    latency_ms=0,
                )
                continue
            runtime_checks.append(name)

        health: dict[str, PluginHealthStatus] = {}
        if runtime_checks:
            health = await self._health_orchestrator.run(
                tool_names=runtime_checks,
                adapter_resolver=self.resolve_tool_adapter_for_preflight,
                context=context,
                concurrency_limit=min(self._max_concurrency, request.concurrency_limit),
            )
        health.update(skipped)
        return {
            name: {
                "healthy": health[name].healthy,
                "reason": health[name].reason,
                "latency_ms": health[name].latency_ms,
            }
            for name in selected
        }
