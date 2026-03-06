"""Result caching helpers for Plugin Platform v2."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from datetime import date, datetime, time as dt_time
from enum import Enum
from pathlib import PurePath
from typing import Any

from pydantic import BaseModel

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


def _stable_json_text(value: Any) -> str:
    """Serialize normalized payload into canonical JSON text."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _normalize_fingerprint_dict_key(value: Any) -> str:
    """Normalize mapping keys into deterministic string representation."""

    if isinstance(value, str):
        return value
    if isinstance(value, Enum):
        return _normalize_fingerprint_dict_key(value.value)
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()
    return str(value)


def _normalize_for_fingerprint(value: Any) -> Any:
    """Normalize nested payload into JSON-safe deterministic structure."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, BaseModel):
        return _normalize_for_fingerprint(value.model_dump(mode="json"))

    if isinstance(value, Enum):
        return _normalize_for_fingerprint(value.value)

    if isinstance(value, Mapping):
        normalized_items: list[tuple[str, Any]] = []
        for key, item in value.items():
            normalized_items.append(
                (_normalize_fingerprint_dict_key(key), _normalize_for_fingerprint(item))
            )
        normalized_items.sort(key=lambda pair: pair[0])
        return {key: item for key, item in normalized_items}

    if isinstance(value, (list, tuple)):
        return [_normalize_for_fingerprint(item) for item in value]

    if isinstance(value, (set, frozenset)):
        normalized_items = [_normalize_for_fingerprint(item) for item in value]
        return sorted(normalized_items, key=_stable_json_text)

    if isinstance(value, PurePath):
        return str(value)

    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()

    return str(value)


def build_result_fingerprint(
    *,
    request: ScanRequest,
    tool_name: str,
    tool_version: str,
    policy_signature: Mapping[str, Any],
) -> str:
    """Build deterministic cache key from request, plugin, and policy context."""

    payload = {
        "targets": [target.model_dump(mode="json") for target in request.targets],
        "tool_name": tool_name,
        "tool_version": tool_version,
        "tool_options": request.options.get(tool_name, {}),
        "global_options": request.options,
        "policy": dict(policy_signature),
    }
    normalized_payload = _normalize_for_fingerprint(payload)
    serialized = _stable_json_text(normalized_payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class ScanResultCache:
    """In-memory cache for scan results with fingerprint keys."""

    def __init__(
        self,
        *,
        default_ttl_seconds: float | None = 300.0,
        max_size: int = 512,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        if default_ttl_seconds is not None and float(default_ttl_seconds) <= 0.0:
            raise ValueError("default_ttl_seconds must be > 0 when provided")
        self._default_ttl_seconds = float(default_ttl_seconds) if default_ttl_seconds is not None else None
        self._max_size = int(max_size)
        self._clock = clock or time.monotonic
        self._storage: OrderedDict[str, tuple[float | None, ScanResult]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._metrics: dict[str, int] = {
            "cache_hit": 0,
            "cache_miss": 0,
            "cache_evict": 0,
        }

    @property
    def metrics(self) -> dict[str, int]:
        """Return cache metrics snapshot."""

        return dict(self._metrics)

    def _now(self) -> float:
        return float(self._clock())

    def _compute_expires_at(self) -> float | None:
        if self._default_ttl_seconds is None:
            return None
        return self._now() + self._default_ttl_seconds

    def _is_expired(self, expires_at: float | None) -> bool:
        return expires_at is not None and expires_at <= self._now()

    def _evict_expired_locked(self) -> int:
        evicted = 0
        for key in list(self._storage.keys()):
            expires_at, _ = self._storage[key]
            if not self._is_expired(expires_at):
                continue
            self._storage.pop(key, None)
            evicted += 1
        if evicted:
            self._metrics["cache_evict"] += evicted
        return evicted

    def _enforce_size_locked(self) -> int:
        evicted = 0
        while len(self._storage) > self._max_size:
            self._storage.popitem(last=False)
            evicted += 1
        if evicted:
            self._metrics["cache_evict"] += evicted
        return evicted

    async def get(self, key: str) -> ScanResult | None:
        async with self._lock:
            item = self._storage.get(key)
            if item is None:
                self._metrics["cache_miss"] += 1
                return None

            expires_at, result = item
            if self._is_expired(expires_at):
                self._storage.pop(key, None)
                self._metrics["cache_miss"] += 1
                self._metrics["cache_evict"] += 1
                return None

            self._storage.move_to_end(key)
            self._metrics["cache_hit"] += 1
            return result.model_copy(deep=True)

    async def set(self, key: str, value: ScanResult) -> None:
        async with self._lock:
            self._evict_expired_locked()
            self._storage[key] = (self._compute_expires_at(), value.model_copy(deep=True))
            self._storage.move_to_end(key)
            self._enforce_size_locked()

    async def clear(self) -> None:
        async with self._lock:
            self._storage.clear()
