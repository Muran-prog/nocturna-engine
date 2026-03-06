"""Async status polling helpers for BaseApiTool."""

from __future__ import annotations

import asyncio
from time import monotonic
from typing import Any

from ..errors import ApiError, ApiTimeoutError


class ApiPollingMixin:
    """Mixin with polling helpers for async API jobs."""

    async def _poll_status(self, task_id: str, interval: float, max_wait: float) -> dict[str, Any]:
        """Poll async task status endpoint until terminal state or timeout.

        Args:
            task_id: Remote scan task identifier.
            interval: Poll interval in seconds.
            max_wait: Max total wait in seconds.

        Returns:
            dict[str, Any]: Last received status payload.

        Raises:
            ApiTimeoutError: If polling exceeds max_wait.
            ApiError: If status payload is malformed.
        """

        if not task_id.strip():
            raise ApiError("Polling task_id must be non-empty.")
        if interval <= 0:
            raise ApiError("Polling interval must be greater than zero.")
        if max_wait <= 0:
            raise ApiError("Polling max_wait must be greater than zero.")

        started = monotonic()
        status_path = self._build_status_path(task_id)
        while True:
            response = await self._request("GET", status_path, retry=True)
            payload = response.body if isinstance(response.body, dict) else {"raw": response.body}
            status = self._extract_poll_status(payload)
            if status in self.terminal_poll_statuses:
                return payload
            elapsed = monotonic() - started
            if elapsed >= max_wait:
                raise ApiTimeoutError(
                    f"Polling timeout for task '{task_id}' after {max_wait:.2f}s."
                )
            await asyncio.sleep(interval)

    def _build_status_path(self, task_id: str) -> str:
        """Build polling path from configurable path template."""

        return self.status_path_template.format(task_id=task_id)

    @staticmethod
    def _extract_poll_status(payload: dict[str, Any]) -> str:
        """Extract normalized status token from polling payload."""

        for key in ("scan_status", "status", "state"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
        return "unknown"
