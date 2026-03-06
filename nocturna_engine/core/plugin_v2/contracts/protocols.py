"""Runtime protocol abstractions for Plugin Platform v2."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable


@runtime_checkable
class SecretAccessor(Protocol):
    """Secret resolution abstraction for runtime context."""

    def get_secret(self, key: str, default: str | None = None) -> str | None:
        """Resolve one secret value."""


@runtime_checkable
class RuntimeCache(Protocol):
    """Async cache abstraction for request/result reuse."""

    async def get(self, key: str) -> Any | None:
        """Read one cache value."""

    async def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        """Store one cache value."""

    async def delete(self, key: str) -> None:
        """Delete one cache value."""


@runtime_checkable
class StorageProvider(Protocol):
    """Ephemeral and persistent storage abstraction."""

    def get_temp_path(self, prefix: str = "nocturna") -> Path:
        """Return a writable temp path for plugin execution."""


@runtime_checkable
class MetricsCollector(Protocol):
    """Metrics abstraction for observability hooks."""

    def increment(self, name: str, value: int = 1, tags: Mapping[str, str] | None = None) -> None:
        """Increment a counter metric."""

    def observe(self, name: str, value: float, tags: Mapping[str, str] | None = None) -> None:
        """Record a histogram-style metric."""
