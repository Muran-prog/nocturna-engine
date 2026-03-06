"""Contracts and runtime primitives for Plugin Platform v2."""

from nocturna_engine.core.plugin_v2.contracts.context import PluginRuntimeContext
from nocturna_engine.core.plugin_v2.contracts.implementations import (
    EnvironmentSecretAccessor,
    InMemoryMetricsCollector,
    InMemoryRuntimeCache,
    LocalTempStorageProvider,
)
from nocturna_engine.core.plugin_v2.contracts.manifest import (
    CapabilityDescriptor,
    CompatibilityInfo,
    ExecutionRequirements,
    HealthProfile,
    PluginManifest,
)
from nocturna_engine.core.plugin_v2.contracts.plugin import BaseToolV2, ToolV2Protocol
from nocturna_engine.core.plugin_v2.contracts.protocols import (
    MetricsCollector,
    RuntimeCache,
    SecretAccessor,
    StorageProvider,
)

__all__ = [
    "BaseToolV2",
    "CapabilityDescriptor",
    "CompatibilityInfo",
    "EnvironmentSecretAccessor",
    "ExecutionRequirements",
    "HealthProfile",
    "InMemoryMetricsCollector",
    "InMemoryRuntimeCache",
    "LocalTempStorageProvider",
    "MetricsCollector",
    "PluginManifest",
    "PluginRuntimeContext",
    "RuntimeCache",
    "SecretAccessor",
    "StorageProvider",
    "ToolV2Protocol",
]
