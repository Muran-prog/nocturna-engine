"""Plugin system v2 execution flow composition."""

from __future__ import annotations

from nocturna_engine.core.plugin_manager.execution.v2.batch import PluginV2BatchExecutionMixin
from nocturna_engine.core.plugin_manager.execution.v2.errors import PluginV2ErrorHandlingMixin
from nocturna_engine.core.plugin_manager.execution.v2.events import PluginV2EventPublishingMixin
from nocturna_engine.core.plugin_manager.execution.v2.limits import PluginV2RuntimeLimitMixin
from nocturna_engine.core.plugin_manager.execution.v2.tool import PluginV2ToolExecutionMixin


class PluginV2ExecutionMixin(
    PluginV2ToolExecutionMixin,
    PluginV2BatchExecutionMixin,
    PluginV2EventPublishingMixin,
    PluginV2RuntimeLimitMixin,
    PluginV2ErrorHandlingMixin,
):
    """V2 execution and preflight orchestration for plugin manager."""

