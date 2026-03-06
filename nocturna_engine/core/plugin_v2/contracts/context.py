"""Plugin runtime context for Plugin Platform v2."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Mapping

from nocturna_engine.core.event_bus import EventBus

from .protocols import MetricsCollector, RuntimeCache, SecretAccessor, StorageProvider


@dataclass(slots=True)
class PluginRuntimeContext:
    """Execution context injected into v2 plugins."""

    event_bus: EventBus
    logger: Any
    config: Mapping[str, Any]
    secrets: SecretAccessor
    cache: RuntimeCache
    cancellation_token: asyncio.Event
    storage: StorageProvider
    metrics: MetricsCollector
    request_metadata: Mapping[str, Any] = field(default_factory=dict)
    policy: Mapping[str, Any] = field(default_factory=dict)
