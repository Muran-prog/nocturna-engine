"""Helpers for enforcing subprocess output-size limits."""

from __future__ import annotations

from .errors import ToolError


class _OutputLimitExceeded(ToolError):
    """Internal sentinel exception for output size limit violations."""


class _OutputLimiter:
    """Shared byte budget for concurrent stdout/stderr readers."""

    def __init__(self, max_bytes: int) -> None:
        self._max_bytes = max_bytes
        self._consumed_bytes = 0

    def consume(self, count: int) -> None:
        self._consumed_bytes += count
        if self._consumed_bytes > self._max_bytes:
            raise _OutputLimitExceeded(
                f"Subprocess output exceeded {self._max_bytes} bytes limit."
            )
