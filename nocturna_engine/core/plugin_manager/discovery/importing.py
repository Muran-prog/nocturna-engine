"""Package importing and trust validation mixin."""

from __future__ import annotations

import importlib
import pkgutil
import re
from collections.abc import Mapping


_SAFE_MODULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

_DEFAULT_TRUSTED_PACKAGE_PREFIXES: tuple[str, ...] = ("nocturna_", "nocturna_engine")


class PluginImportMixin:
    """Import packages and validate trusted namespaces."""

    def _import_package_modules(self, package_name: str) -> list[dict[str, str]]:
        """Import package and submodules to force subclass registration.

        Args:
            package_name: Root package name.

        Returns:
            list[dict[str, str]]: Collected import failures with reason metadata.
        """

        failures: list[dict[str, str]] = []

        if not _SAFE_MODULE_NAME_RE.fullmatch(package_name):
            failure = {
                "module": package_name,
                "reason": "invalid_module_name",
                "reason_code": "invalid_module_name",
                "error": f"Package name '{package_name}' contains invalid characters.",
                "error_type": "PluginRegistrationError",
            }
            failures.append(failure)
            self._logger.warning("plugin_package_invalid_name", module=package_name)
            return failures

        try:
            root = importlib.import_module(package_name)
        except Exception as exc:
            failure = self._build_import_failure(module_name=package_name, error=exc)
            failures.append(failure)
            self._logger.warning(
                "plugin_module_import_failed",
                module=failure["module"],
                reason=failure["reason"],
                reason_code=failure["reason_code"],
                error=failure["error"],
                error_type=failure["error_type"],
            )
            return failures

        if not hasattr(root, "__path__"):
            return failures
        for _, module_name, _ in pkgutil.walk_packages(root.__path__, root.__name__ + "."):
            try:
                importlib.import_module(module_name)
            except Exception as exc:
                failure = self._build_import_failure(module_name=module_name, error=exc)
                failures.append(failure)
                self._logger.warning(
                    "plugin_module_import_failed",
                    module=failure["module"],
                    reason=failure["reason"],
                    reason_code=failure["reason_code"],
                    error=failure["error"],
                    error_type=failure["error_type"],
                )
        return failures

    def _is_trusted_package(self, package_name: str) -> bool:
        """Validate package_name against trusted namespace prefixes."""
        if not package_name or not _SAFE_MODULE_NAME_RE.fullmatch(package_name):
            return False
        for prefix in self._get_trusted_prefixes():
            if package_name == prefix or package_name.startswith(prefix + ".") or package_name.startswith(prefix):
                return True
        return False

    def _get_trusted_prefixes(self) -> tuple[str, ...]:
        """Return configured or default trusted package prefixes."""
        plugins_config = self._config.get("plugins")
        if isinstance(plugins_config, Mapping):
            custom = plugins_config.get("trusted_package_prefixes")
            if isinstance(custom, (list, tuple)) and custom:
                return tuple(str(p).strip() for p in custom if str(p).strip())
        return _DEFAULT_TRUSTED_PACKAGE_PREFIXES

    @staticmethod
    def _build_import_failure(*, module_name: str, error: BaseException) -> dict[str, str]:
        return {
            "module": module_name,
            "reason": "module_import_failed",
            "reason_code": "module_import_failed",
            "error": str(error),
            "error_type": type(error).__name__,
        }
