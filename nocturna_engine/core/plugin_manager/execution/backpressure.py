"""Backpressure helpers for plugin execution."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class PluginBackpressureExecutionMixin:
    """Backpressure and adaptive concurrency helpers."""

    async def _execute_with_backpressure(
        self,
        *,
        request: ScanRequest,
        tool_names: list[str],
        concurrency_limit: int,
    ) -> list[ScanResult]:
        if not tool_names:
            return []

        max_workers = max(1, min(concurrency_limit, len(tool_names)))
        queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=max_workers * 2)
        results: dict[str, ScanResult] = {}

        async def producer() -> None:
            for tool_name in tool_names:
                await queue.put(tool_name)
            for _ in range(max_workers):
                await queue.put(None)

        async def worker() -> None:
            while True:
                tool_name = await queue.get()
                try:
                    if tool_name is None:
                        return
                    try:
                        results[tool_name] = await self.execute_tool(tool_name, request)
                    except Exception as exc:
                        results[tool_name] = self._build_failure_result(
                            request=request,
                            tool_name=tool_name,
                            started_at=datetime.now(UTC),
                            error_message=str(exc),
                            metadata={"reason": "worker_error"},
                        )
                finally:
                    queue.task_done()

        producer_task = asyncio.create_task(producer())
        workers = [asyncio.create_task(worker()) for _ in range(max_workers)]
        await queue.join()
        await producer_task
        await asyncio.gather(*workers, return_exceptions=True)
        return [results[name] for name in tool_names if name in results]

    def _resolve_adaptive_concurrency(
        self,
        *,
        selected: list[str],
        runnable: list[str],
        request: ScanRequest,
    ) -> int:
        base = min(self._max_concurrency, request.concurrency_limit)
        if not selected:
            return max(1, base)
        health_ratio = len(runnable) / len(selected)
        adaptive = int(round(base * (0.5 + (health_ratio / 2.0))))
        speed = str(request.metadata.get("speed", "normal")).lower()
        if speed == "fast":
            adaptive += 1
        if speed == "safe":
            adaptive -= 1
        return max(1, min(base, adaptive))

