"""Core execution flow composition."""

from __future__ import annotations

from nocturna_engine.core.plugin_manager.execution.core.ai_selection import PluginAISelectionMixin
from nocturna_engine.core.plugin_manager.execution.core.batch import PluginExecutionBatchMixin
from nocturna_engine.core.plugin_manager.execution.core.dispatch import PluginDispatchValidationMixin
from nocturna_engine.core.plugin_manager.execution.core.egress import PluginSubprocessEgressMixin
from nocturna_engine.core.plugin_manager.execution.core.scope import PluginScopeValidationMixin


class PluginExecutionCoreMixin(
    PluginExecutionBatchMixin,
    PluginDispatchValidationMixin,
    PluginSubprocessEgressMixin,
    PluginScopeValidationMixin,
    PluginAISelectionMixin,
):
    """Dispatch and batch execution orchestration for plugins."""

