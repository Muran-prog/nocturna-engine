"""Concrete implementations of runtime protocol abstractions."""

from __future__ import annotations

import asyncio
import copy
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping


class EnvironmentSecretAccessor:
    """Simple secret accessor backed by environment variables."""

    def __init__(
        self,
        prefix: str = "NOCTURNA_SECRET_",
        source_name: str = "unknown",
        logger: Any = None,
    ) -> None:
        self._prefix = prefix
        self._source_name = source_name
        self._logger = logger

    def get_secret(self, key: str, default: str | None = None) -> str | None:
        env_key = f"{self._prefix}{key}".upper()
        result = os.getenv(env_key, default)
        if self._logger is not None:
            self._logger.info(
                "secret_accessed",
                source=self._source_name,
                secret_key=key,
                resolved=(result is not None),
            )
        return result


class InMemoryRuntimeCache:
    """Async-safe in-memory cache with optional TTL support."""

    def __init__(self) -> None:
        self._storage: dict[str, tuple[float | None, Any]] = {}
        self._lock = asyncio.Lock()
        self._clock = time.monotonic

    def _now(self) -> float:
        return float(self._clock())

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            item = self._storage.get(key)
            if item is None:
                return None
            expires_at, value = item
            if expires_at is not None and expires_at <= self._now():
                self._storage.pop(key, None)
                return None
            return copy.deepcopy(value)

    async def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None:
        async with self._lock:
            expires_at: float | None = None
            if ttl_seconds is not None:
                expires_at = self._now() + max(0.0, float(ttl_seconds))
            self._storage[key] = (expires_at, copy.deepcopy(value))

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._storage.pop(key, None)


class LocalTempStorageProvider:
    """Filesystem temp-storage provider with tracking and cleanup."""

    def __init__(self, root: Path | None = None, max_total_bytes: int | None = None) -> None:
        self._root = root
        self._max_total_bytes = max_total_bytes
        self._created_paths: list[Path] = []

    def get_temp_path(self, prefix: str = "nocturna") -> Path:
        if self._max_total_bytes is not None:
            usage = self.total_disk_usage()
            if usage >= self._max_total_bytes:
                raise RuntimeError(
                    f"Temp storage quota exceeded: {usage}/{self._max_total_bytes} bytes"
                )
        if self._root is not None:
            self._root.mkdir(parents=True, exist_ok=True)
            path = Path(tempfile.mkdtemp(prefix=f"{prefix}-", dir=str(self._root)))
        else:
            path = Path(tempfile.mkdtemp(prefix=f"{prefix}-"))
        self._created_paths.append(path)
        return path

    def cleanup(self) -> None:
        """Remove all temp directories created by this provider."""
        import shutil

        for path in reversed(self._created_paths):
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
        self._created_paths.clear()

    def total_disk_usage(self) -> int:
        """Return total bytes used by all tracked temp directories."""
        total = 0
        for path in self._created_paths:
            if path.exists():
                for file in path.rglob("*"):
                    if file.is_file():
                        total += file.stat().st_size
        return total


class InMemoryMetricsCollector:
    """Lightweight metrics sink for tests and local runtime."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self.histograms: dict[str, list[float]] = {}

    def increment(self, name: str, value: int = 1, tags: Mapping[str, str] | None = None) -> None:
        _ = tags
        self.counters[name] = self.counters.get(name, 0) + int(value)

    def observe(self, name: str, value: float, tags: Mapping[str, str] | None = None) -> None:
        _ = tags
        bucket = self.histograms.setdefault(name, [])
        bucket.append(float(value))
