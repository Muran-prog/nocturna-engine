"""Initialization/shutdown orchestration for plugin lifecycle."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, bounded_gather, retry_async, with_timeout


class PluginLifecycleOrchestrationMixin:
    """Initialization and teardown orchestration helpers."""

    async def initialize_plugins(self) -> None:
        """Initialize all registered plugins.

        Failures are logged and isolated; the manager continues with healthy
        plugins.
        """

        if not self._registry:
            return

        factories = [self._build_initializer(tool_name) for tool_name in self.list_registered_tools()]
        await bounded_gather(
            factories,
            concurrency_limit=min(self._max_concurrency, max(1, len(factories))),
            return_exceptions=False,
        )

    async def shutdown_plugins(self) -> None:
        """Shutdown all active plugins with graceful degradation."""

        if not self._instances:
            return

        factories = [self._build_shutdown(tool_name) for tool_name in self.list_active_tools()]
        await bounded_gather(
            factories,
            concurrency_limit=min(self._max_concurrency, max(1, len(factories))),
            return_exceptions=False,
        )
        self._instances.clear()

    def _build_initializer(self, tool_name: str) -> Callable[[], Awaitable[None]]:
        """Create deferred plugin initialization operation.

        Args:
            tool_name: Tool name.

        Returns:
            Callable[[], Awaitable[None]]: Async callable operation.
        """

        async def _initialize() -> None:
            await self._initialize_tool_if_needed(tool_name)

        return _initialize

    def _build_shutdown(self, tool_name: str) -> Callable[[], Awaitable[None]]:
        """Create deferred plugin teardown operation.

        Args:
            tool_name: Tool name.

        Returns:
            Callable[[], Awaitable[None]]: Async callable operation.
        """

        async def _shutdown() -> None:
            tool_instance = self._instances.get(tool_name)
            if tool_instance is None:
                return
            timeout_seconds = float(getattr(tool_instance, "timeout_seconds", self._default_timeout_seconds))

            async def _teardown() -> None:
                await with_timeout(
                    tool_instance.teardown(),
                    timeout_seconds=timeout_seconds,
                    operation_name=f"tool_teardown:{tool_name}",
                )

            try:
                await retry_async(_teardown, retries=0, retry_exceptions=TRANSIENT_RETRY_EXCEPTIONS)
            except Exception as exc:
                self._logger.warning("tool_teardown_failed", tool=tool_name, error=str(exc))

        return _shutdown
