"""Circuit-breaker and quarantine controls for unstable plugins."""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass


@dataclass(slots=True)
class CircuitState:
    """Mutable circuit state for one plugin."""

    failures: int = 0
    opened_until: float | None = None
    last_error: str | None = None


class CircuitBreakerRegistry:
    """Tracks plugin failures and enforces temporary quarantine."""

    def __init__(self) -> None:
        self._states: dict[str, CircuitState] = {}
        self._lock = threading.Lock()

    def is_quarantined(self, plugin_name: str) -> bool:
        with self._lock:
            state = self._states.get(plugin_name)
            if state is None or state.opened_until is None:
                return False
            if state.opened_until <= time.monotonic():
                state.opened_until = None
                state.failures = 0
                state.last_error = None
                return False
            return True

    def quarantine_reason(self, plugin_name: str) -> str | None:
        with self._lock:
            state = self._states.get(plugin_name)
            if state is None or state.opened_until is None:
                return None
            remaining = max(0.0, state.opened_until - time.monotonic())
            return f"circuit_open:{remaining:.1f}s"

    def record_success(self, plugin_name: str) -> None:
        with self._lock:
            state = self._states.setdefault(plugin_name, CircuitState())
            state.failures = 0
            state.opened_until = None
            state.last_error = None

    def record_failure(
        self,
        plugin_name: str,
        *,
        threshold: int,
        quarantine_seconds: float,
        error_message: str,
    ) -> bool:
        """Record one failure and return whether plugin is quarantined now."""

        with self._lock:
            state = self._states.setdefault(plugin_name, CircuitState())
            state.failures += 1
            state.last_error = error_message
            if state.failures >= threshold:
                state.opened_until = time.monotonic() + quarantine_seconds
                return True
            return False

