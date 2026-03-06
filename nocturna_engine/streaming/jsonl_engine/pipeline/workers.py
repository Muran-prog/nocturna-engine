"""Producer/consumer worker loops used by JSONL pipeline orchestrator."""

from __future__ import annotations

import asyncio

from nocturna_engine.streaming.jsonl_engine.errors import (
    JsonlEngineCancelledError,
    JsonlHookExecutionError,
)
from nocturna_engine.streaming.jsonl_engine.models import JsonlIssueEnvelope
from nocturna_engine.streaming.jsonl_engine.pipeline.runtime import JsonlPipelineRuntime
from nocturna_engine.streaming.jsonl_engine.runner import (
    JsonlSubprocessRunner,
    ProcessProtocol,
)

_SENTINEL = None  # Sentinel value signaling producer completion via the queue.

async def producer_loop(
    *,
    runtime: JsonlPipelineRuntime,
    runner: JsonlSubprocessRunner,
    process: ProcessProtocol,
) -> None:
    """Read stdout chunks, parse JSONL, and enqueue record envelopes.

    Args:
        runtime: Shared pipeline runtime state.
        runner: Subprocess runner dependency.
        process: Process handle.
    """

    try:
        async for chunk in runner.iter_stdout_chunks(
            process=process,
            output_budget=runtime.output_budget,
            cancel_event=runtime.cancel_event,
            chunk_size=runtime.config.parser.chunk_size,
        ):
            runtime.metrics.add_bytes_read(len(chunk))
            batch = runtime.parser.feed(chunk, stats=runtime.stats)
            for issue in batch.issues:
                await runtime.handle_issue(issue)
                runtime.malformed_policy.validate(runtime.stats)
            for record in batch.records:
                await runtime.queue.put(record)

        final_batch = runtime.parser.flush(stats=runtime.stats)
        for issue in final_batch.issues:
            await runtime.handle_issue(issue)
            runtime.malformed_policy.validate(runtime.stats)
        for record in final_batch.records:
            await runtime.queue.put(record)
    finally:
        await runtime.queue.put(_SENTINEL)
        runtime.producer_done.set()


async def consumer_loop(*, runtime: JsonlPipelineRuntime) -> None:
    """Drain record queue and emit record/progress hooks.

    Args:
        runtime: Shared pipeline runtime state.
    """

    since_last_record_heartbeat = 0
    every_records = runtime.config.heartbeat.every_records

    while True:
        if runtime.cancel_event is not None and runtime.cancel_event.is_set():
            raise JsonlEngineCancelledError("JSONL consumer cancelled.")
        try:
            envelope = await asyncio.wait_for(runtime.queue.get(), timeout=0.1)
        except asyncio.TimeoutError:
            continue
        if envelope is _SENTINEL:
            break

        try:
            await runtime.runtime_hooks.emit_record(envelope)
        except Exception as callback_error:
            issue = JsonlIssueEnvelope(
                line_number=envelope.line_number,
                raw_line=envelope.raw_line,
                error=JsonlHookExecutionError(
                    f"on_record hook failed: {callback_error}"
                ),
                source="hook",
            )
            await runtime.handle_issue(issue)
            continue

        runtime.metrics.increment_emitted_records()
        if runtime.config.collect_records:
            runtime.records.append(envelope.payload)

        if every_records is not None:
            since_last_record_heartbeat += 1
            if since_last_record_heartbeat >= every_records:
                since_last_record_heartbeat = 0
                await runtime.emit_progress()


async def heartbeat_loop(*, runtime: JsonlPipelineRuntime) -> None:
    """Emit timed progress snapshots while producer/consumer are active.

    Args:
        runtime: Shared pipeline runtime state.
    """

    interval = runtime.config.heartbeat.every_seconds
    if interval is None:
        return
    while True:
        await asyncio.sleep(interval)
        if runtime.producer_done.is_set() and runtime.queue.empty():
            return
        if runtime.cancel_event is not None and runtime.cancel_event.is_set():
            return
        await runtime.emit_progress()
