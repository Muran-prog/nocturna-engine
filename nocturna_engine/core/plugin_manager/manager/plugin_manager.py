"""Plugin manager composition root."""

from __future__ import annotations

import asyncio
from typing import Any, Mapping

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_manager.discovery import PluginDiscoveryMixin
from nocturna_engine.core.plugin_manager.execution import PluginExecutionMixin
from nocturna_engine.core.plugin_manager.lifecycle import PluginLifecycleMixin
from nocturna_engine.core.plugin_manager.manager.feature_flags import PluginManagerFeatureFlagsMixin
from nocturna_engine.core.plugin_manager.manager.planning import PluginManagerPlanningMixin
from nocturna_engine.core.plugin_manager.manager.runtime_context import PluginManagerRuntimeContextMixin
from nocturna_engine.core.plugin_v2 import (
    CapabilityAwarePlanner,
    CircuitBreakerRegistry,
    DeterministicPluginRegistry,
    InMemoryMetricsCollector,
    InMemoryRuntimeCache,
    LocalTempStorageProvider,
    PluginPolicy,
    PluginPolicyEngine,
    PolicyBuildResult,
    PolicyDecision,
    PreflightHealthOrchestrator,
    ScanResultCache,
)
from nocturna_engine.interfaces import BaseTool


class PluginManager(
    PluginDiscoveryMixin,
    PluginLifecycleMixin,
    PluginExecutionMixin,
    PluginManagerFeatureFlagsMixin,
    PluginManagerRuntimeContextMixin,
    PluginManagerPlanningMixin,
):
    """Registry-based manager for tool plugin lifecycle and execution."""

    def __init__(
        self,
        event_bus: EventBus | None = None,
        logger: BoundLogger | None = None,
        default_timeout_seconds: float = 60.0,
        max_concurrency: int = 4,
        config: Mapping[str, Any] | None = None,
        feature_flags: Mapping[str, bool] | None = None,
    ) -> None:
        """Initialize plugin manager.

        Args:
            event_bus: Shared event bus instance.
            logger: Optional logger.
            default_timeout_seconds: Fallback timeout for plugin operations.
            max_concurrency: Max concurrent plugin operations.
            config: Optional runtime configuration map.
            feature_flags: Optional feature flags.
        """

        self._event_bus = event_bus or EventBus()
        self._logger = logger or structlog.get_logger("plugin_manager")
        self._default_timeout_seconds = default_timeout_seconds
        self._max_concurrency = max_concurrency
        self._config: dict[str, Any] = dict(config or {})
        self._feature_flags = self._normalize_feature_flags(feature_flags)
        self._registry: dict[str, type[BaseTool]] = {}
        self._instances: dict[str, BaseTool] = {}
        self._tool_setup_failures: dict[str, dict[str, Any]] = {}
        self._last_discovery_report: dict[str, Any] = {
            "package_name": None,
            "strict": False,
            "import_failures": [],
        }
        self._tool_init_locks: dict[str, asyncio.Lock] = {}
        self._tool_init_locks_guard = asyncio.Lock()
        self._deterministic_registry = DeterministicPluginRegistry(
            logger=self._logger.bind(component="deterministic_registry")
        )
        self._runtime_cache = InMemoryRuntimeCache()
        self._result_cache = ScanResultCache()
        self._metrics = InMemoryMetricsCollector()
        self._storage = LocalTempStorageProvider()
        self._policy_engine = PluginPolicyEngine()
        self._planner = CapabilityAwarePlanner(policy_engine=self._policy_engine)
        self._circuit_breaker = CircuitBreakerRegistry()
        self._health_orchestrator = PreflightHealthOrchestrator(
            logger=self._logger.bind(component="preflight")
        )

    def build_policy_result(
        self,
        policy_payload: Mapping[str, Any] | None = None,
        *,
        fail_closed: bool = False,
    ) -> PolicyBuildResult:
        """Build effective policy result via the internal policy engine.

        Args:
            policy_payload: Optional policy override mapping.
            fail_closed: Whether to use fail-closed validation semantics.

        Returns:
            PolicyBuildResult: Built policy with validation metadata.
        """
        return self._policy_engine.build_policy_result(policy_payload, fail_closed=fail_closed)

    def evaluate_manifest_payload(
        self,
        manifest_payload: Mapping[str, Any],
        policy: PluginPolicy,
    ) -> PolicyDecision:
        """Evaluate a tool manifest against a policy via the internal policy engine.

        Args:
            manifest_payload: Machine-readable tool manifest mapping.
            policy: Active policy to evaluate against.

        Returns:
            PolicyDecision: Allow/deny decision with reason metadata.
        """
        return self._policy_engine.evaluate_manifest_payload(manifest_payload, policy)

    async def __aenter__(self) -> "PluginManager":
        """Enter async context and initialize registered plugins.

        Returns:
            PluginManager: Ready manager instance.
        """

        await self.initialize_plugins()
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: Any) -> None:
        """Exit async context and shutdown plugin instances.

        Args:
            exc_type: Exception type from context.
            exc: Exception instance from context.
            tb: Traceback object.
        """

        await self.shutdown_plugins()
