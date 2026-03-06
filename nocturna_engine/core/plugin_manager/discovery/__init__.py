"""Plugin discovery and registration mixin."""

from __future__ import annotations

from .class_utils import PluginClassUtilsMixin
from .importing import PluginImportMixin
from .registration import PluginRegistrationMixin
from .scanning import PluginScanningMixin


class PluginDiscoveryMixin(
    PluginClassUtilsMixin,
    PluginImportMixin,
    PluginRegistrationMixin,
    PluginScanningMixin,
):
    """Discovery and registry operations for tool plugins."""


__all__ = ["PluginDiscoveryMixin"]
