"""Shared runtime state and callback helpers for JSONL streaming pipeline."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.errors import (
    JsonlEngineError,
    JsonlHookExecutionError,
)
from nocturna_engine.streaming.jsonl_engine.hooks import JsonlEngineHooks
from nocturna_engine.streaming.jsonl_engine.metrics import JsonlMetrics
from nocturna_engine.streaming.jsonl_engine.models import (
    JsonlEngineConfig,
    JsonlIssueEnvelope,
    JsonlRecordEnvelope,
    JsonlStreamStats,
)
from nocturna_engine.streaming.jsonl_engine.parser import JsonlChunkParser
from nocturna_engine.streaming.jsonl_engine.policies import (
    ErrorPolicy,
    ExitCodePolicy,
    MalformedThresholdPolicy,
)
from nocturna_engine.streaming.jsonl_engine.utils import OutputBudget


@dataclass(slots=True)
class JsonlPipelineRuntime:
    """Shared mutable state for one pipeline execution."""

    config: JsonlEngineConfig
    runtime_hooks: JsonlEngineHooks
    error_policy: ErrorPolicy
    exit_code_policy: ExitCodePolicy
    malformed_policy: MalformedThresholdPolicy
    logger: BoundLogger
    metrics: JsonlMetrics
    parser: JsonlChunkParser
    records: list[dict[str, Any]]
    queue: asyncio.Queue[JsonlRecordEnvelope]
    producer_done: asyncio.Event
    output_budget: OutputBudget
    cancel_event: asyncio.Event | None

    @property
    def stats(self) -> JsonlStreamStats:
        """Return mutable runtime stats object.

        Returns:
            JsonlStreamStats: Runtime stats.
        """

        return self.metrics.stats

    async def handle_issue(self, issue: JsonlIssueEnvelope) -> None:
        """Handle issue envelope via logging, hooks, and error policy.

        Args:
            issue: Runtime issue envelope.
        """

        self.logger.warning(
            "jsonl_pipeline_issue",
            source=issue.source,
            line_number=issue.line_number,
            error=str(issue.error),
        )
        try:
            await self.runtime_hooks.emit_error(issue)
        except Exception as callback_error:
            self.logger.warning(
                "jsonl_on_error_hook_failed",
                error=str(callback_error),
            )
            if self.error_policy.should_raise(callback_error):
                raise JsonlHookExecutionError(
                    f"on_error hook failed: {callback_error}"
                ) from callback_error
        if self.error_policy.should_raise(issue.error):
            if isinstance(issue.error, JsonlEngineError):
                raise issue.error
            raise JsonlEngineError(str(issue.error))

    async def emit_progress(self) -> None:
        """Emit progress snapshot and route hook failures via issue handling."""

        snapshot = self.stats.copy()
        try:
            await self.runtime_hooks.emit_progress(snapshot)
        except Exception as callback_error:
            issue = JsonlIssueEnvelope(
                line_number=None,
                raw_line=None,
                error=JsonlHookExecutionError(
                    f"on_progress hook failed: {callback_error}"
                ),
                source="hook",
            )
            await self.handle_issue(issue)
