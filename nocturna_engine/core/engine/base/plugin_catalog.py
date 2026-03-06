"""Plugin catalog facade for Nocturna Engine."""

from __future__ import annotations

from typing import Any

from nocturna_engine.core.plugin_manager import PluginManager


class _PluginCatalogFacade:
    """Plugin introspection facade used by AI clients and automation."""

    def __init__(self, plugin_manager: PluginManager) -> None:
        self._plugin_manager = plugin_manager

    def describe_all(self, machine_readable: bool = True) -> dict[str, Any]:
        return self._plugin_manager.describe_all_tools(machine_readable=machine_readable)

    def describe(self, tool_name: str, include_schema: bool = False) -> dict[str, Any] | None:
        return self._plugin_manager.describe_tool(tool_name, include_schema=include_schema)
