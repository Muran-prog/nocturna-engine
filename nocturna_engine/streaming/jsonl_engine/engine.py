"""Public facade for running reusable JSONL streaming subprocess pipelines."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.hooks import JsonlEngineHooks, compose_hooks
from nocturna_engine.streaming.jsonl_engine.models import (
    JsonlEngineConfig,
    JsonlEngineResult,
    JsonlRecordEnvelope,
)
from nocturna_engine.streaming.jsonl_engine.pipeline import JsonlStreamingPipeline
from nocturna_engine.streaming.jsonl_engine.runner import JsonlSubprocessRunner


class JsonlStreamingEngine:
    """Reusable facade that runs JSONL process streams with configurable policies."""

    def __init__(
        self,
        *,
        runner: JsonlSubprocessRunner | None = None,
        logger: BoundLogger | None = None,
    ) -> None:
        """Initialize engine with injectable subprocess runner.

        Args:
            runner: Optional subprocess runner override.
            logger: Optional structured logger.
        """

        self._logger = logger or structlog.get_logger("jsonl_streaming_engine")
        self._runner = runner or JsonlSubprocessRunner(
            chunk_size=8192,
            logger=self._logger.bind(component="runner"),
        )

    async def run(
        self,
        *,
        config: JsonlEngineConfig,
        hooks: JsonlEngineHooks | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> JsonlEngineResult:
        """Execute streaming run and return normalized engine result.

        Args:
            config: Engine runtime configuration.
            hooks: Optional callback hooks.
            cancel_event: Optional external cancellation signal.

        Returns:
            JsonlEngineResult: Normalized execution payload.
        """

        pipeline = JsonlStreamingPipeline(
            runner=self._runner,
            logger=self._logger.bind(component="pipeline"),
        )
        return await pipeline.run(config=config, hooks=hooks, cancel_event=cancel_event)

    async def iter_records(
        self,
        *,
        config: JsonlEngineConfig,
        hooks: JsonlEngineHooks | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> AsyncIterator[JsonlRecordEnvelope]:
        """Yield parsed records via async iterator while process is running.

        Args:
            config: Engine runtime configuration.
            hooks: Optional user hooks that should run in parallel with iterator.
            cancel_event: Optional external cancellation signal.

        Yields:
            JsonlRecordEnvelope: Parsed record envelopes.
        """

        queue: asyncio.Queue[JsonlRecordEnvelope | None] = asyncio.Queue(
            maxsize=max(1, config.queue_maxsize)
        )

        async def _on_record(envelope: JsonlRecordEnvelope) -> None:
            await queue.put(envelope)

        iterator_hooks = JsonlEngineHooks(on_record=_on_record)
        merged_hooks = compose_hooks(iterator_hooks, hooks)
        run_config = config.model_copy(update={"collect_records": False})

        async def _runner_task() -> None:
            try:
                await self.run(config=run_config, hooks=merged_hooks, cancel_event=cancel_event)
            finally:
                await queue.put(None)

        task = asyncio.create_task(_runner_task(), name="jsonl-engine-iterator")
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
