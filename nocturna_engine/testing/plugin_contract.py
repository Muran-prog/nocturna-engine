"""Contract test-kit for validating v2-ready plugin classes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nocturna_engine.interfaces.base_tool import BaseTool

from nocturna_engine.core.plugin_v2 import build_manifest_from_tool_class


@dataclass(slots=True, frozen=True)
class PluginContractReport:
    """Validation report for one plugin class."""

    plugin_id: str
    display_name: str
    version: str
    has_option_schema: bool
    supported_targets: tuple[str, ...]
    supported_phases: tuple[str, ...]


def validate_plugin_contract(tool_class: type[BaseTool]) -> PluginContractReport:
    """Validate plugin class against baseline v2 contract expectations."""

    manifest = build_manifest_from_tool_class(tool_class)
    if not manifest.id:
        raise AssertionError("Plugin manifest id is required.")
    if not manifest.version:
        raise AssertionError("Plugin manifest version is required.")
    if not manifest.display_name:
        raise AssertionError("Plugin manifest display_name is required.")
    return PluginContractReport(
        plugin_id=manifest.id,
        display_name=manifest.display_name,
        version=manifest.version,
        has_option_schema=bool(manifest.option_schema),
        supported_targets=manifest.supported_targets,
        supported_phases=manifest.supported_phases,
    )


def assert_plugin_contract(tool_class: type[BaseTool], **expected: Any) -> PluginContractReport:
    """Validate plugin and assert selected expected contract fields."""

    report = validate_plugin_contract(tool_class)
    for key, value in expected.items():
        actual = getattr(report, key)
        if actual != value:
            raise AssertionError(f"Contract mismatch for '{key}': expected {value!r}, got {actual!r}")
    return report

