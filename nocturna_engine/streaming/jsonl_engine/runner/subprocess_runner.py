"""Concrete subprocess runner assembled from focused runner mixins."""

from __future__ import annotations

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.runner.lifecycle import RunnerLifecycleMixin
from nocturna_engine.streaming.jsonl_engine.runner.protocols import ProcessFactory
from nocturna_engine.streaming.jsonl_engine.runner.start import RunnerStartMixin
from nocturna_engine.streaming.jsonl_engine.runner.streams import RunnerStreamsMixin


class JsonlSubprocessRunner(
    RunnerStartMixin,
    RunnerStreamsMixin,
    RunnerLifecycleMixin,
):
    """Runs subprocesses with secure defaults and bounded stream readers."""

    def __init__(
        self,
        *,
        process_factory: ProcessFactory | None = None,
        chunk_size: int = 8192,
        allowed_binaries: frozenset[str] | None = None,
        logger: BoundLogger | None = None,
    ) -> None:
        """Initialize subprocess runner.

        Args:
            process_factory: Optional process factory for testing.
            chunk_size: Read chunk size for stdout/stderr.
            allowed_binaries: Optional frozenset of permitted binary names.
            logger: Optional structured logger.
        """

        self._process_factory = process_factory
        self._chunk_size = chunk_size
        self._allowed_binaries = allowed_binaries
        self._logger = logger or structlog.get_logger("jsonl_subprocess_runner")

