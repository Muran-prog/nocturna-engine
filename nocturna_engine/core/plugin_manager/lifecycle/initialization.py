"""Tool-instance setup, locking, and instantiation for plugin lifecycle."""

from __future__ import annotations

import asyncio

from nocturna_engine.exceptions import PluginExecutionError, PluginRegistrationError
from nocturna_engine.interfaces import BaseTool
from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, retry_async, with_timeout


class PluginInitializationMixin:
    """Tool-instance setup and construction helpers."""

    async def _ensure_tool_instance(self, tool_name: str) -> BaseTool | None:
        """Ensure plugin instance exists and is initialized.

        Args:
            tool_name: Registered plugin name.

        Returns:
            BaseTool | None: Live plugin instance.
        """

        return await self._initialize_tool_if_needed(tool_name)

    async def _initialize_tool_if_needed(self, tool_name: str) -> BaseTool | None:
        """Initialize one tool exactly once even under concurrent access."""

        if tool_name in self._instances:
            return self._instances[tool_name]
        if tool_name not in self._registry:
            raise PluginExecutionError(f"Tool not registered: {tool_name}")

        lock = await self._tool_init_lock(tool_name)
        async with lock:
            existing = self._instances.get(tool_name)
            if existing is not None:
                self._clear_tool_setup_failure(tool_name)
                return existing

            tool_class = self._registry[tool_name]
            tool_instance = self._instantiate_tool(tool_class, tool_name)
            timeout_seconds = float(getattr(tool_instance, "timeout_seconds", self._default_timeout_seconds))
            retries = int(getattr(tool_instance, "max_retries", 1))

            async def _setup() -> None:
                await with_timeout(
                    tool_instance.setup(),
                    timeout_seconds=timeout_seconds,
                    operation_name=f"tool_setup:{tool_name}",
                )

            try:
                await retry_async(_setup, retries=retries, retry_exceptions=TRANSIENT_RETRY_EXCEPTIONS)
                self._instances[tool_name] = tool_instance
                self._clear_tool_setup_failure(tool_name)
                await self._event_bus.publish("on_tool_initialized", {"tool": tool_name})
            except Exception as exc:
                setup_failure = self._build_setup_failure_state(tool_name=tool_name, error=exc)
                self._tool_setup_failures[tool_name] = setup_failure
                self._logger.warning(
                    "tool_setup_failed",
                    tool=tool_name,
                    error=setup_failure["error"],
                    reason_code=setup_failure["reason_code"],
                    exc_info=True,
                )
                await self._event_bus.publish(
                    "on_tool_error",
                    self._build_setup_error_event_payload(
                        tool_name=tool_name,
                        setup_failure=setup_failure,
                    ),
                )

            return self._instances.get(tool_name)

    async def _tool_init_lock(self, tool_name: str) -> asyncio.Lock:
        """Return per-tool async lock used by setup path."""

        existing = self._tool_init_locks.get(tool_name)
        if existing is not None:
            return existing
        async with self._tool_init_locks_guard:
            lock = self._tool_init_locks.get(tool_name)
            if lock is None:
                lock = asyncio.Lock()
                self._tool_init_locks[tool_name] = lock
            return lock

    def _instantiate_tool(self, tool_class: type[BaseTool], tool_name: str) -> BaseTool:
        """Instantiate plugin class with logger injection when possible.

        Args:
            tool_class: Plugin class.
            tool_name: Plugin name.

        Returns:
            BaseTool: Plugin instance.

        Raises:
            PluginRegistrationError: If class cannot be instantiated.
        """

        try:
            return tool_class(logger=self._logger.bind(tool=tool_name))
        except TypeError:
            try:
                return tool_class()
            except Exception as exc:
                raise PluginRegistrationError(
                    f"Unable to instantiate tool '{tool_name}': {exc}"
                ) from exc
