"""Plugin manager feature flags and registry descriptions."""

from __future__ import annotations

from typing import Any, Mapping


class PluginManagerFeatureFlagsMixin:
    """Feature flag and runtime config operations for plugin manager."""

    @property
    def feature_flags(self) -> dict[str, bool]:
        """Return immutable copy of runtime feature flags."""

        return dict(self._feature_flags)

    def is_feature_enabled(self, flag_name: str) -> bool:
        """Check whether one feature flag is enabled."""

        return bool(self._feature_flags.get(flag_name, False))

    def describe_tool(self, tool_name: str, *, include_schema: bool = False) -> dict[str, Any] | None:
        """Return machine-readable tool description from deterministic registry."""

        return self._deterministic_registry.describe(tool_name, include_schema=include_schema)

    def describe_all_tools(self, *, machine_readable: bool = True) -> dict[str, Any]:
        """Return tool catalog for AI and human introspection."""

        return self._deterministic_registry.describe_all(machine_readable=machine_readable)

    def apply_runtime_config(self, config: Mapping[str, Any]) -> None:
        """Apply runtime config and merge feature flags without reinitialization."""

        self._config = dict(config)
        features = self._config.get("features", {})
        if isinstance(features, Mapping):
            merged = dict(self._feature_flags)
            merged.update({str(key): bool(value) for key, value in features.items()})
            self._feature_flags = merged

    @staticmethod
    def _normalize_feature_flags(feature_flags: Mapping[str, bool] | None) -> dict[str, bool]:
        defaults = {
            "plugin_system_v2": False,
            "event_contract_v2": False,
            "ai_api_v2": False,
            "phase_dag_pipeline": False,
            "policy_fail_closed": True,
            "legacy_discovery_subclasses_fallback": False,
            "strict_plugin_discovery": False,
        }
        if not feature_flags:
            return defaults
        normalized = dict(defaults)
        normalized.update({str(key): bool(value) for key, value in feature_flags.items()})
        return normalized
