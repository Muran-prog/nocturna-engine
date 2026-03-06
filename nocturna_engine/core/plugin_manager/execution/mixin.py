"""Plugin execution mixin composition."""

from __future__ import annotations

from nocturna_engine.core.plugin_manager.execution.backpressure import PluginBackpressureExecutionMixin
from nocturna_engine.core.plugin_manager.execution.core import PluginExecutionCoreMixin
from nocturna_engine.core.plugin_manager.execution.legacy import PluginLegacyExecutionMixin
from nocturna_engine.core.plugin_manager.execution.policy import PluginExecutionPolicyMixin
from nocturna_engine.core.plugin_manager.execution.results import PluginExecutionResultMixin
from nocturna_engine.core.plugin_manager.execution.v2 import PluginV2ExecutionMixin


class PluginExecutionMixin(
    PluginExecutionCoreMixin,
    PluginLegacyExecutionMixin,
    PluginV2ExecutionMixin,
    PluginBackpressureExecutionMixin,
    PluginExecutionPolicyMixin,
    PluginExecutionResultMixin,
):
    """Execution and result normalization for plugins."""

