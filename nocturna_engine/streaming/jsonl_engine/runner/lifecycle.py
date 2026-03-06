"""Lifecycle control behavior for the JSONL subprocess runner."""

from __future__ import annotations

import asyncio

from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.errors import JsonlEngineCancelledError
from nocturna_engine.streaming.jsonl_engine.runner.protocols import ProcessProtocol


class RunnerLifecycleMixin:
    """Mixin with wait/kill/drain process lifecycle logic."""

    _logger: BoundLogger

    async def wait_for_exit(
        self,
        *,
        process: ProcessProtocol,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Wait for process exit while honoring cancellation.

        Args:
            process: Process handle.
            cancel_event: Optional cancellation signal.

        Returns:
            int: Process return code.

        Raises:
            JsonlEngineCancelledError: If cancellation signal is set before exit.
        """

        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise JsonlEngineCancelledError("JSONL process wait was cancelled.")
            if process.returncode is not None:
                return int(process.returncode)
            try:
                return await asyncio.wait_for(process.wait(), timeout=0.25)
            except asyncio.TimeoutError:
                continue

    async def drain(self, *, process: ProcessProtocol, timeout_seconds: float = 1.0) -> int | None:
        """Wait briefly for process termination after a kill signal.

        Args:
            process: Process handle.
            timeout_seconds: Max wait duration.

        Returns:
            int | None: Return code when available.
        """

        if process.returncode is not None:
            return int(process.returncode)
        try:
            return await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            return process.returncode

    def kill(self, process: ProcessProtocol) -> None:
        """Terminate process safely if still running.

        Args:
            process: Process handle.
        """

        if process.returncode is not None:
            return
        try:
            process.kill()
        except ProcessLookupError:
            self._logger.debug("jsonl_process_already_stopped")

