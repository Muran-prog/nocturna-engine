"""Hook interfaces for record, error, progress, and completion callbacks."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from nocturna_engine.streaming.jsonl_engine.models import (
    JsonlEngineResult,
    JsonlIssueEnvelope,
    JsonlRecordEnvelope,
    JsonlStreamStats,
)
from nocturna_engine.streaming.jsonl_engine.utils import maybe_await

RecordHook = Callable[[JsonlRecordEnvelope], Awaitable[None] | None]
ErrorHook = Callable[[JsonlIssueEnvelope], Awaitable[None] | None]
ProgressHook = Callable[[JsonlStreamStats], Awaitable[None] | None]
CompleteHook = Callable[[JsonlEngineResult], Awaitable[None] | None]


@dataclass(slots=True)
class JsonlEngineHooks:
    """Container for optional JSONL engine callbacks."""

    on_record: RecordHook | None = None
    on_error: ErrorHook | None = None
    on_progress: ProgressHook | None = None
    on_complete: CompleteHook | None = None

    async def emit_record(self, envelope: JsonlRecordEnvelope) -> None:
        """Invoke record callback if configured.

        Args:
            envelope: Parsed record envelope.
        """

        if self.on_record is None:
            return
        await maybe_await(self.on_record(envelope))

    async def emit_error(self, issue: JsonlIssueEnvelope) -> None:
        """Invoke error callback if configured.

        Args:
            issue: Issue envelope.
        """

        if self.on_error is None:
            return
        await maybe_await(self.on_error(issue))

    async def emit_progress(self, stats: JsonlStreamStats) -> None:
        """Invoke progress callback if configured.

        Args:
            stats: Runtime stream stats snapshot.
        """

        if self.on_progress is None:
            return
        await maybe_await(self.on_progress(stats))

    async def emit_complete(self, result: JsonlEngineResult) -> None:
        """Invoke completion callback if configured.

        Args:
            result: Final engine result.
        """

        if self.on_complete is None:
            return
        await maybe_await(self.on_complete(result))


def compose_hooks(*hooks: JsonlEngineHooks | None) -> JsonlEngineHooks:
    """Compose multiple hook containers into one sequential dispatcher.

    Args:
        hooks: Hook containers to merge.

    Returns:
        JsonlEngineHooks: Composite dispatcher preserving call order.
    """

    active = [hook for hook in hooks if hook is not None]
    if not active:
        return JsonlEngineHooks()
    if len(active) == 1:
        return active[0]

    async def on_record(envelope: JsonlRecordEnvelope) -> None:
        for hook in active:
            await hook.emit_record(envelope)

    async def on_error(issue: JsonlIssueEnvelope) -> None:
        for hook in active:
            await hook.emit_error(issue)

    async def on_progress(stats: JsonlStreamStats) -> None:
        for hook in active:
            await hook.emit_progress(stats)

    async def on_complete(result: JsonlEngineResult) -> None:
        for hook in active:
            await hook.emit_complete(result)

    return JsonlEngineHooks(
        on_record=on_record,
        on_error=on_error,
        on_progress=on_progress,
        on_complete=on_complete,
    )

