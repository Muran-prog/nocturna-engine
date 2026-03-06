"""Stream reading behavior for the JSONL subprocess runner."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from nocturna_engine.streaming.jsonl_engine.errors import JsonlEngineCancelledError
from nocturna_engine.streaming.jsonl_engine.runner.protocols import ProcessProtocol
from nocturna_engine.streaming.jsonl_engine.utils import OutputBudget, sanitize_output


class RunnerStreamsMixin:
    """Mixin with stdout/stderr stream consumption logic."""

    _chunk_size: int

    async def iter_stdout_chunks(
        self,
        *,
        process: ProcessProtocol,
        output_budget: OutputBudget,
        cancel_event: asyncio.Event | None = None,
        chunk_size: int | None = None,
    ) -> AsyncIterator[bytes]:
        """Yield stdout chunks while enforcing output budgets and cancellation.

        Args:
            process: Process handle.
            output_budget: Shared byte-budget tracker.
            cancel_event: Optional external cancellation signal.

        Yields:
            bytes: Stdout chunk bytes.

        Raises:
            JsonlEngineCancelledError: If cancellation signal is set.
        """

        stream = process.stdout
        if stream is None:
            return

        read_size = self._chunk_size if chunk_size is None else chunk_size
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise JsonlEngineCancelledError("JSONL stream reading was cancelled.")
            chunk = await stream.read(read_size)
            if not chunk:
                break
            output_budget.consume_stdout(len(chunk))
            yield chunk

    async def collect_stderr(
        self,
        *,
        process: ProcessProtocol,
        output_budget: OutputBudget,
        cancel_event: asyncio.Event | None = None,
        chunk_size: int | None = None,
    ) -> str:
        """Read full stderr concurrently with stdout consumption.

        Args:
            process: Process handle.
            output_budget: Shared byte-budget tracker.
            cancel_event: Optional external cancellation signal.

        Returns:
            str: Sanitized stderr text.
        """

        stream = process.stderr
        if stream is None:
            return ""

        read_size = self._chunk_size if chunk_size is None else chunk_size
        chunks = bytearray()
        while True:
            if cancel_event is not None and cancel_event.is_set() and process.returncode is not None:
                break
            chunk = await stream.read(read_size)
            if not chunk:
                break
            output_budget.consume_stderr(len(chunk))
            chunks.extend(chunk)
        return sanitize_output(chunks.decode("utf-8", errors="replace"))

