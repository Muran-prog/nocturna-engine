"""Counters and timing helpers for JSONL streaming runs."""

from __future__ import annotations

from time import perf_counter

from nocturna_engine.streaming.jsonl_engine.models import JsonlStreamStats


class JsonlMetrics:
    """Tracks runtime counters and derived metrics for one engine execution."""

    def __init__(self, stats: JsonlStreamStats | None = None) -> None:
        """Initialize metrics tracker.

        Args:
            stats: Optional mutable stats object to update.
        """

        self._stats = stats or JsonlStreamStats()
        self._started_at = perf_counter()

    @property
    def stats(self) -> JsonlStreamStats:
        """Return mutable stats object.

        Returns:
            JsonlStreamStats: Runtime stats.
        """

        return self._stats

    def add_bytes_read(self, count: int) -> None:
        """Increment total bytes read counter.

        Args:
            count: Byte count.
        """

        self._stats.bytes_read += max(0, int(count))

    def increment_emitted_records(self) -> None:
        """Increment emitted record counter by one."""

        self._stats.emitted_records += 1

    def finalize(self) -> JsonlStreamStats:
        """Finalize duration and throughput metrics.

        Returns:
            JsonlStreamStats: Updated stats object.
        """

        duration = max(0.0, perf_counter() - self._started_at)
        self._stats.duration_seconds = duration
        if duration > 0.0:
            self._stats.throughput_records_per_second = (
                self._stats.emitted_records / duration
            )
        else:
            self._stats.throughput_records_per_second = 0.0
        return self._stats

