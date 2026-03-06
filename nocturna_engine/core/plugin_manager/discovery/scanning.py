"""Plugin scanning and discovery orchestration mixin."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.exceptions import PluginRegistrationError
from nocturna_engine.interfaces import BaseTool


class PluginScanningMixin:
    """Discover plugins by scanning packages and collecting reports."""

    def discover_plugins(self, package_name: str | None = None) -> list[str]:
        """Discover and register plugin subclasses.

        Args:
            package_name: Optional package path to import recursively.

        Returns:
            list[str]: Sorted list of registered plugin names.
        """

        strict_discovery = self._is_strict_discovery_enabled()
        discovery_report: dict[str, Any] = {
            "package_name": package_name,
            "strict": strict_discovery,
            "import_failures": [],
        }

        if package_name:
            import_failures = self._import_package_modules(package_name)
            discovery_report["import_failures"] = import_failures
            if strict_discovery and import_failures:
                self._last_discovery_report = discovery_report
                first_failure = import_failures[0]
                raise PluginRegistrationError(
                    "Strict plugin discovery failed for "
                    f"'{package_name}' while importing '{first_failure['module']}': "
                    f"{first_failure['error']}"
                )

        discovered: list[str] = []
        deterministic_classes: list[type[BaseTool]] = []
        legacy_classes: list[type[BaseTool]] = []
        if package_name:
            deterministic_classes = self._deterministic_registry.discover_classes(package_name)
            if self.is_feature_enabled("legacy_discovery_subclasses_fallback"):
                legacy_classes = self._filter_classes_by_package(
                    self._iter_subclasses(BaseTool),
                    package_name,
                )
        else:
            # Keep backward compatibility for discover_plugins() without package_name.
            legacy_classes = self._iter_subclasses(BaseTool)

        deterministic_set = set(deterministic_classes)
        for subclass in self._iter_unique_classes(
            deterministic_classes,
            legacy_classes,
        ):
            try:
                source = "discovery" if subclass in deterministic_set else "legacy_subclasses"
                discovered.append(self.register_tool_class(subclass, source=source))
            except PluginRegistrationError:
                continue
        self._last_discovery_report = discovery_report
        return sorted(set(discovered))

    def get_last_discovery_report(self) -> dict[str, Any]:
        """Return normalized report from the latest discovery attempt."""

        report = self._last_discovery_report
        failures = report.get("import_failures", [])
        normalized_failures: list[dict[str, str]] = []
        if isinstance(failures, list):
            for item in failures:
                if not isinstance(item, Mapping):
                    continue
                normalized_failures.append(
                    {
                        "module": str(item.get("module") or ""),
                        "reason": str(item.get("reason") or "module_import_failed"),
                        "reason_code": str(item.get("reason_code") or "module_import_failed"),
                        "error": str(item.get("error") or ""),
                        "error_type": str(item.get("error_type") or ""),
                    }
                )

        return {
            "package_name": report.get("package_name"),
            "strict": bool(report.get("strict", False)),
            "import_failures": normalized_failures,
        }

    def _is_strict_discovery_enabled(self) -> bool:
        plugins_config = self._config.get("plugins")
        if isinstance(plugins_config, Mapping) and "strict_discovery" in plugins_config:
            return bool(plugins_config.get("strict_discovery"))
        return self.is_feature_enabled("strict_plugin_discovery")
