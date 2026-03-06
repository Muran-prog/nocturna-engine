"""Deterministic plugin registry and manifest extraction for v2."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from nocturna_engine.exceptions import PluginRegistrationError, ValidationError
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.utils.validators import validate_plugin_name

from .contracts import (
    CapabilityDescriptor,
    CompatibilityInfo,
    ExecutionRequirements,
    HealthProfile,
    PluginManifest,
)


def _normalize_name(tool_class: type[BaseTool]) -> str:
    raw_name = getattr(tool_class, "name", "") or tool_class.__name__.lower()
    try:
        return validate_plugin_name(raw_name)
    except ValidationError as exc:
        raise PluginRegistrationError(str(exc)) from exc


def _extract_options_model(tool_class: type[BaseTool]) -> type[BaseModel] | None:
    candidate = getattr(tool_class, "options_model", None)
    if isinstance(candidate, type) and issubclass(candidate, BaseModel):
        return candidate
    return None


def _normalize_capabilities(value: Any) -> tuple[CapabilityDescriptor, ...]:
    if value is None:
        return tuple()
    if isinstance(value, tuple) and all(isinstance(item, CapabilityDescriptor) for item in value):
        return value

    result: list[CapabilityDescriptor] = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, CapabilityDescriptor):
                result.append(item)
            elif isinstance(item, str):
                result.append(CapabilityDescriptor(name=item.strip().lower()))
            elif isinstance(item, dict):
                result.append(CapabilityDescriptor.model_validate(item))
    return tuple(result)


def _resolve_requirement_flag(
    tool_class: type[BaseTool],
    *,
    attr_name: str,
    inferred_default: bool = False,
) -> bool:
    """Resolve execution requirement with compatibility-friendly fallback."""

    if hasattr(tool_class, attr_name):
        return bool(getattr(tool_class, attr_name))
    return bool(inferred_default)


def build_manifest_from_tool_class(tool_class: type[BaseTool]) -> PluginManifest:
    """Build v2 manifest from explicit metadata or legacy tool attributes."""

    explicit = getattr(tool_class, "__plugin_manifest__", None)
    if isinstance(explicit, PluginManifest):
        manifest = explicit.model_copy(deep=True)
    else:
        plugin_id = _normalize_name(tool_class)
        options_model = _extract_options_model(tool_class)
        capabilities = _normalize_capabilities(getattr(tool_class, "capabilities", None))
        if not capabilities:
            capabilities = tuple(
                CapabilityDescriptor(name=phase, category="phase")
                for phase in getattr(tool_class, "supported_phases", tuple())
            )

        binary_name = str(getattr(tool_class, "binary_name", "") or "").strip()
        requires_network = _resolve_requirement_flag(
            tool_class,
            attr_name="requires_network",
            inferred_default=bool(getattr(tool_class, "requires_api", False)),
        )
        requires_filesystem = _resolve_requirement_flag(
            tool_class,
            attr_name="requires_filesystem",
            inferred_default=bool(binary_name),
        )
        manifest = PluginManifest(
            id=plugin_id,
            version=str(getattr(tool_class, "version", "0.1.0")),
            display_name=str(getattr(tool_class, "display_name", tool_class.__name__)),
            capabilities=capabilities,
            supported_targets=tuple(getattr(tool_class, "supported_target_types", tuple())),
            supported_phases=tuple(getattr(tool_class, "supported_phases", tuple())),
            option_schema=options_model.model_json_schema() if options_model is not None else {},
            execution_requirements=ExecutionRequirements(
                subprocess=bool(binary_name),
                network=requires_network,
                filesystem=requires_filesystem,
                required_binaries=(binary_name,) if binary_name else tuple(),
                max_timeout_seconds=(
                    float(getattr(tool_class, "timeout_seconds"))
                    if hasattr(tool_class, "timeout_seconds")
                    else None
                ),
                max_output_bytes=(
                    int(getattr(tool_class, "max_output_size"))
                    if hasattr(tool_class, "max_output_size")
                    else None
                ),
            ),
            health_profile=HealthProfile(
                startup_check=bool(hasattr(tool_class, "health_check")),
            ),
            compatibility=CompatibilityInfo(
                legacy_names=(plugin_id,),
                deprecated=bool(getattr(tool_class, "deprecated", False)),
                deprecation_message=getattr(tool_class, "deprecation_message", None),
                replacement_plugin_id=getattr(tool_class, "replacement_plugin_id", None),
            ),
        )

    options_model = _extract_options_model(tool_class)
    if options_model is not None and not manifest.option_schema:
        manifest.option_schema = options_model.model_json_schema()
    if not manifest.compatibility.legacy_names:
        manifest.compatibility.legacy_names = (manifest.id,)
    return manifest


@dataclass(slots=True, frozen=True)
class PluginRegistration:
    """Deterministic plugin registration entry."""

    tool_class: type[BaseTool]
    manifest: PluginManifest
    options_model: type[BaseModel] | None
    source: str
    is_legacy: bool


class DeterministicPluginRegistry:
    """Explicit plugin registry with deterministic discovery order."""

    def __init__(self, logger: Any) -> None:
        self._logger = logger
        self._entries: dict[str, PluginRegistration] = {}

    def register(self, tool_class: type[BaseTool], *, source: str = "manual") -> PluginRegistration:
        plugin_name = _normalize_name(tool_class)
        manifest = build_manifest_from_tool_class(tool_class)
        registration = PluginRegistration(
            tool_class=tool_class,
            manifest=manifest,
            options_model=_extract_options_model(tool_class),
            source=source,
            is_legacy=not hasattr(tool_class, "execute_v2"),
        )

        existing = self._entries.get(plugin_name)
        if existing is not None and existing.tool_class is not tool_class:
            raise PluginRegistrationError(f"Plugin name already registered: {plugin_name}")

        self._entries[plugin_name] = registration
        return registration

    def discover_classes(self, package_name: str) -> list[type[BaseTool]]:
        """Discover tool classes by inspecting imported module members."""

        module_names = self._collect_module_names(package_name)
        discovered: list[type[BaseTool]] = []
        seen: set[type[BaseTool]] = set()

        for module_name in module_names:
            try:
                module = importlib.import_module(module_name)
            except Exception as exc:
                self._logger.warning(
                    "plugin_module_import_failed",
                    module=module_name,
                    error=str(exc),
                )
                continue

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if obj in seen or not issubclass(obj, BaseTool) or obj is BaseTool:
                    continue
                if not obj.__module__.startswith(package_name):
                    continue
                seen.add(obj)
                discovered.append(obj)

        return sorted(discovered, key=lambda item: (item.__module__, item.__qualname__))

    def list_registered_names(self) -> list[str]:
        return sorted(self._entries.keys())

    def get_registration(self, plugin_name: str) -> PluginRegistration | None:
        return self._entries.get(plugin_name)

    def describe(self, plugin_name: str, *, include_schema: bool = False) -> dict[str, Any] | None:
        registration = self.get_registration(plugin_name)
        if registration is None:
            return None
        payload = registration.manifest.machine_readable(include_schema=include_schema)
        payload["implementation"] = {
            "class_name": registration.tool_class.__name__,
            "module": registration.tool_class.__module__,
            "source": registration.source,
            "legacy_adapter_required": registration.is_legacy,
        }
        return payload

    def describe_all(self, *, machine_readable: bool = True) -> dict[str, Any]:
        if machine_readable:
            return {
                name: self.describe(name, include_schema=False)
                for name in self.list_registered_names()
            }
        return {
            "plugins": [
                {
                    "name": name,
                    "display_name": self._entries[name].manifest.display_name,
                    "capabilities": [item.name for item in self._entries[name].manifest.capabilities],
                    "targets": list(self._entries[name].manifest.supported_targets),
                }
                for name in self.list_registered_names()
            ]
        }

    @staticmethod
    def _collect_module_names(package_name: str) -> list[str]:
        root = importlib.import_module(package_name)
        if not hasattr(root, "__path__"):
            return [package_name]
        names = [package_name]
        names.extend(
            sorted(
                module_name
                for _, module_name, _ in pkgutil.walk_packages(root.__path__, root.__name__ + ".")
            )
        )
        return names


def declare_plugin(
    *,
    manifest: PluginManifest,
    options_model: type[BaseModel] | None = None,
) -> Any:
    """Decorator for declarative v2 plugin registration metadata."""

    def _decorator(tool_class: type[BaseTool]) -> type[BaseTool]:
        setattr(tool_class, "__plugin_manifest__", manifest.model_copy(deep=True))
        if options_model is not None:
            setattr(tool_class, "options_model", options_model)
        return tool_class

    return _decorator
