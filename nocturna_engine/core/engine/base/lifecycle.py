"""Lifecycle and registration primitives for Nocturna Engine."""

from __future__ import annotations

import asyncio
from typing import Any, Sequence

from structlog.stdlib import BoundLogger

from nocturna_engine.core.engine.fingerprint_index import FindingFingerprintIndex
from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.pipeline import Pipeline
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.interfaces import BaseAnalyzer, BaseReporter, BaseTool
from nocturna_engine.services import ConfigService, LoggingService

from .plugin_catalog import _PluginCatalogFacade


class _EngineLifecycleMixin:
    def __init__(
        self,
        plugin_manager: PluginManager | None = None,
        event_bus: EventBus | None = None,
        pipeline: Pipeline | None = None,
        config_service: ConfigService | None = None,
        logging_service: LoggingService | None = None,
        analyzers: Sequence[BaseAnalyzer] | None = None,
        reporters: Sequence[BaseReporter] | None = None,
        logger: BoundLogger | None = None,
    ) -> None:
        """Initialize engine with dependency injection.

        Args:
            plugin_manager: Optional plugin manager instance.
            event_bus: Optional shared event bus.
            pipeline: Optional pipeline implementation.
            config_service: Optional configuration provider.
            logging_service: Optional logging configuration service.
            analyzers: Optional default analyzers.
            reporters: Optional default reporters.
            logger: Optional explicit logger.
        """

        self.logging_service = logging_service or LoggingService()
        self.logger = logger or self.logging_service.get_logger("nocturna_engine")
        self.config_service = config_service or ConfigService()
        self.event_bus = event_bus or EventBus(logger=self.logger.bind(component="event_bus"))
        self.plugin_manager = plugin_manager or PluginManager(
            event_bus=self.event_bus,
            logger=self.logger.bind(component="plugin_manager"),
        )
        self.pipeline = pipeline or Pipeline(logger=self.logger.bind(component="pipeline"))
        self.plugins = _PluginCatalogFacade(self.plugin_manager)
        self._analyzers: list[BaseAnalyzer] = list(analyzers or [])
        self._reporters: list[BaseReporter] = list(reporters or [])
        self.finding_index = FindingFingerprintIndex()
        self._started = False
        self._start_lock = asyncio.Lock()
        self._config: dict[str, Any] = {}
        self._configure_default_pipeline()

    async def __aenter__(self) -> "NocturnaEngine":
        """Enter async context and start engine.

        Returns:
            NocturnaEngine: Started engine instance.
        """

        await self.start()
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: Any) -> None:
        """Exit async context and stop engine.

        Args:
            exc_type: Exception type from context.
            exc: Exception instance from context.
            tb: Traceback object.
        """

        await self.stop()

    def register_tool(self, tool_class: type[BaseTool]) -> str:
        """Register tool plugin class.

        Args:
            tool_class: Tool class inheriting `BaseTool`.

        Returns:
            str: Normalized plugin name.
        """

        return self.plugin_manager.register_tool_class(tool_class)

    def register_analyzer(self, analyzer: BaseAnalyzer) -> None:
        """Register analyzer component.

        Args:
            analyzer: Analyzer instance.
        """

        self._analyzers.append(analyzer)

    def register_reporter(self, reporter: BaseReporter) -> None:
        """Register reporter component.

        Args:
            reporter: Reporter instance.
        """

        self._reporters.append(reporter)

    def subscribe(self, event_name: str, handler: Any) -> None:
        """Subscribe handler to event bus.

        Args:
            event_name: Event name.
            handler: Async event handler.
        """

        self.event_bus.subscribe(event_name, handler)

    def unsubscribe(self, event_name: str, handler: Any) -> None:
        """Unsubscribe handler from event bus.

        Args:
            event_name: Event name.
            handler: Existing handler callback.
        """

        self.event_bus.unsubscribe(event_name, handler)

    async def start(self) -> None:
        """Start engine and initialize registered plugins."""

        if self._started:
            return
        async with self._start_lock:
            if self._started:
                return
            self._config = self.config_service.load()
            finding_index_path = self._config.get("engine", {}).get("finding_index_path")
            if isinstance(finding_index_path, str) and finding_index_path.strip():
                try:
                    self.finding_index.configure_storage(finding_index_path.strip())
                except Exception as exc:
                    self.logger.warning(
                        "finding_index_load_failed",
                        path=finding_index_path,
                        error=str(exc),
                    )
            self.plugin_manager.apply_runtime_config(self._config)
            self.event_bus.configure_v2_bridge(
                enabled=self.plugin_manager.is_feature_enabled("event_contract_v2")
            )
            trusted_prefixes = self.plugin_manager._get_trusted_prefixes()
            for package_name in self._config.get("plugins", {}).get("auto_discover_packages", []):
                if not self.plugin_manager._is_trusted_package(package_name):
                    self.logger.warning(
                        "auto_discover_untrusted_package",
                        package_name=package_name,
                        trusted_prefixes=list(trusted_prefixes),
                    )
                    continue
                self.plugin_manager.discover_plugins(package_name)
            await self.plugin_manager.initialize_plugins()
            self._started = True
            self.logger.info("engine_started", tool_count=len(self.plugin_manager.list_registered_tools()))

    async def stop(self) -> None:
        """Stop engine and release managed resources."""

        async with self._start_lock:
            if not self._started:
                return
            try:
                await self.plugin_manager.shutdown_plugins()
            finally:
                await self.event_bus.close()
                self._started = False
                self.logger.info("engine_stopped")
