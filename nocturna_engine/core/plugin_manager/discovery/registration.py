"""Plugin registration and tool access mixin."""

from __future__ import annotations

from nocturna_engine.exceptions import PluginRegistrationError, ValidationError
from nocturna_engine.interfaces import BaseTool
from nocturna_engine.utils.validators import validate_plugin_name


class PluginRegistrationMixin:
    """Register, list, and access tool plugins."""

    def register_tool_class(self, tool_class: type[BaseTool], *, source: str = "manual") -> str:
        """Register one plugin class in the registry.

        Args:
            tool_class: `BaseTool` subclass.

        Returns:
            str: Normalized plugin name.

        Raises:
            PluginRegistrationError: If class is invalid or duplicate.
        """

        if not issubclass(tool_class, BaseTool):
            raise PluginRegistrationError("Plugin class must inherit BaseTool.")
        try:
            plugin_name = validate_plugin_name(getattr(tool_class, "name", ""))
        except ValidationError as exc:
            raise PluginRegistrationError(str(exc)) from exc
        existing = self._registry.get(plugin_name)
        if existing is not None and existing is not tool_class:
            raise PluginRegistrationError(f"Plugin name already registered: {plugin_name}")
        self._registry[plugin_name] = tool_class
        self._deterministic_registry.register(tool_class, source=source)
        return plugin_name

    def list_registered_tools(self) -> list[str]:
        """Return plugin names registered in the manager.

        Returns:
            list[str]: Registered tool names.
        """

        return sorted(self._registry.keys())

    def list_active_tools(self) -> list[str]:
        """Return plugin names with live initialized instances.

        Returns:
            list[str]: Active tool names.
        """

        return sorted(self._instances.keys())

    def get_tool(self, tool_name: str) -> BaseTool | None:
        """Get active plugin instance.

        Args:
            tool_name: Plugin name.

        Returns:
            BaseTool | None: Initialized tool instance or None.
        """

        return self._instances.get(tool_name)
