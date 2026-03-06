"""Backpressure-safe orchestration pipeline for JSONL streaming runs."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.errors import (
    JsonlEngineCancelledError,
    JsonlEngineError,
    JsonlEngineTimeoutError,
    JsonlHookExecutionError,
)
from nocturna_engine.streaming.jsonl_engine.hooks import JsonlEngineHooks
from nocturna_engine.streaming.jsonl_engine.metrics import JsonlMetrics
from nocturna_engine.streaming.jsonl_engine.models import (
    EngineErrorKind,
    JsonlEngineConfig,
    JsonlEngineResult,
    JsonlRecordEnvelope,
)
from nocturna_engine.streaming.jsonl_engine.parser import JsonlChunkParser
from nocturna_engine.streaming.jsonl_engine.pipeline.runtime import JsonlPipelineRuntime
from nocturna_engine.streaming.jsonl_engine.pipeline.workers import (
    consumer_loop,
    heartbeat_loop,
    producer_loop,
)
from nocturna_engine.streaming.jsonl_engine.policies import build_policies
from nocturna_engine.streaming.jsonl_engine.runner import JsonlSubprocessRunner
from nocturna_engine.streaming.jsonl_engine.utils import (
    OutputBudget,
    format_command_for_log,
    normalize_command,
)


class JsonlStreamingPipeline:
    """Coordinates process runner, parser, queue consumer, and callbacks."""

    def __init__(
        self,
        *,
        runner: JsonlSubprocessRunner,
        logger: BoundLogger | None = None,
    ) -> None:
        """Initialize pipeline orchestrator.

        Args:
            runner: Subprocess runner dependency.
            logger: Optional structured logger.
        """

        self._runner = runner
        self._logger = logger or structlog.get_logger("jsonl_streaming_pipeline")

    async def run(
        self,
        *,
        config: JsonlEngineConfig,
        hooks: JsonlEngineHooks | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> JsonlEngineResult:
        """Execute one JSONL process run with producer/consumer orchestration.

        Args:
            config: Engine runtime configuration.
            hooks: Optional callback hooks.
            cancel_event: Optional external cancellation signal.

        Returns:
            JsonlEngineResult: Normalized execution result.
        """

        runtime_hooks = hooks or JsonlEngineHooks()
        error_policy, exit_code_policy, malformed_policy = build_policies(config.policies)

        command = normalize_command(config.command)
        masked_command = format_command_for_log(command)
        metrics = JsonlMetrics()
        parser = JsonlChunkParser(
            config=config.parser,
            logger=self._logger.bind(component="parser"),
        )

        process = await self._runner.start(command)
        runtime = JsonlPipelineRuntime(
            config=config,
            runtime_hooks=runtime_hooks,
            error_policy=error_policy,
            exit_code_policy=exit_code_policy,
            malformed_policy=malformed_policy,
            logger=self._logger,
            metrics=metrics,
            parser=parser,
            records=[],
            queue=asyncio.Queue[JsonlRecordEnvelope](maxsize=config.queue_maxsize),
            producer_done=asyncio.Event(),
            output_budget=OutputBudget(
                max_output_bytes=config.limits.max_output_bytes,
                max_stderr_bytes=config.limits.max_stderr_bytes,
            ),
            cancel_event=cancel_event,
        )

        return_code = -1
        stderr_text = ""
        fatal_error: JsonlEngineError | None = None

        stderr_task = asyncio.create_task(
            self._runner.collect_stderr(
                process=process,
                output_budget=runtime.output_budget,
                cancel_event=cancel_event,
                chunk_size=config.parser.chunk_size,
            ),
            name="jsonl-pipeline-stderr",
        )
        producer_task = asyncio.create_task(
            producer_loop(runtime=runtime, runner=self._runner, process=process),
            name="jsonl-pipeline-producer",
        )
        consumer_task = asyncio.create_task(
            consumer_loop(runtime=runtime),
            name="jsonl-pipeline-consumer",
        )
        heartbeat_task = asyncio.create_task(
            heartbeat_loop(runtime=runtime),
            name="jsonl-pipeline-heartbeat",
        )
        wait_task = asyncio.create_task(
            self._runner.wait_for_exit(process=process, cancel_event=cancel_event),
            name="jsonl-pipeline-wait",
        )

        try:
            async with asyncio.timeout(config.timeout_seconds):
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise JsonlEngineCancelledError("JSONL execution cancelled.")

                    for task in (producer_task, consumer_task, heartbeat_task, stderr_task):
                        if task.done():
                            task_exception = task.exception()
                            if task_exception is not None:
                                if isinstance(task_exception, JsonlEngineError):
                                    raise task_exception
                                raise JsonlEngineError(str(task_exception))

                    if wait_task.done():
                        return_code = wait_task.result()
                        break
                    await asyncio.sleep(0.05)

                await producer_task
                await consumer_task
                if not heartbeat_task.done():
                    heartbeat_task.cancel()
                await asyncio.gather(heartbeat_task, return_exceptions=True)
                stderr_text = await stderr_task
                runtime.exit_code_policy.validate(return_code=return_code, stderr=stderr_text)
        except asyncio.TimeoutError:
            fatal_error = JsonlEngineTimeoutError(
                f"JSONL process timed out after {config.timeout_seconds:.2f}s: {masked_command}"
            )
            self._logger.warning("jsonl_pipeline_timeout", error=str(fatal_error))
            self._runner.kill(process)
        except JsonlEngineError as exc:
            fatal_error = exc
            self._logger.warning("jsonl_pipeline_failed", error=str(exc))
            self._runner.kill(process)
        except Exception as exc:  # pragma: no cover - defensive fallback.
            fatal_error = JsonlEngineError(str(exc))
            self._logger.warning("jsonl_pipeline_unexpected_failure", error=str(exc))
            self._runner.kill(process)
        finally:
            await self._runner.drain(process=process, timeout_seconds=1.0)
            if process.returncode is None:
                # Process survived drain — force kill and reap to prevent zombie.
                self._runner.kill(process)
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._logger.error(
                        "jsonl_zombie_process_leak",
                        pid=process.pid,
                    )
            await self._finalize_tasks(
                [producer_task, consumer_task, heartbeat_task, stderr_task, wait_task]
            )

            if wait_task.done() and return_code == -1:
                try:
                    return_code = wait_task.result()
                except (Exception, asyncio.CancelledError):
                    if process.returncode is not None:
                        return_code = int(process.returncode)
            elif process.returncode is not None and return_code == -1:
                return_code = int(process.returncode)

            if not stderr_text and stderr_task.done() and not stderr_task.cancelled():
                try:
                    stderr_text = stderr_task.result()
                except Exception as stderr_error:
                    if fatal_error is None:
                        fatal_error = JsonlEngineError(str(stderr_error))

        runtime.stats.bytes_read = max(runtime.stats.bytes_read, runtime.output_budget.total_bytes)
        finalized_stats = runtime.metrics.finalize()
        result = JsonlEngineResult(
            records=runtime.records,
            stats=finalized_stats,
            stderr=stderr_text,
            return_code=return_code,
            command=masked_command,
            duration_seconds=finalized_stats.duration_seconds,
            error=str(fatal_error) if fatal_error is not None else None,
            error_kind=fatal_error.kind if fatal_error is not None else None,
            was_cancelled=(
                fatal_error is not None and fatal_error.kind == EngineErrorKind.CANCELLED
            ),
        )

        try:
            await runtime.runtime_hooks.emit_complete(result)
        except Exception as callback_error:
            self._logger.warning(
                "jsonl_on_complete_hook_failed",
                error=str(callback_error),
            )
            if result.error is None and runtime.error_policy.should_raise(callback_error):
                hook_error = JsonlHookExecutionError(
                    f"on_complete hook failed: {callback_error}"
                )
                result.error = str(hook_error)
                result.error_kind = hook_error.kind

        return result

    async def _finalize_tasks(self, tasks: Iterable[asyncio.Task[object]]) -> None:
        """Cancel pending tasks and await them safely.

        Args:
            tasks: Task iterable.
        """

        for task in tasks:
            if task.done():
                continue
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
