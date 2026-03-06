"""Plugin lifecycle mixin."""

from __future__ import annotations

from .initialization import PluginInitializationMixin
from .orchestration import PluginLifecycleOrchestrationMixin
from .setup_failures import PluginSetupFailureMixin


class PluginLifecycleMixin(
    PluginSetupFailureMixin,
    PluginLifecycleOrchestrationMixin,
    PluginInitializationMixin,
):
    """Initialization, teardown, and instance management for plugins."""


__all__ = ["PluginLifecycleMixin"]
