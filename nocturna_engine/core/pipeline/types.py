"""Pipeline context and type aliases."""

from __future__ import annotations

import copy
import threading
from datetime import datetime
from typing import Any, Awaitable, Callable

import structlog

_merge_logger = structlog.get_logger("pipeline.context.merge")

# ---------------------------------------------------------------------------
# List-valued keys that must be concatenated (not overwritten) during merge.
# ---------------------------------------------------------------------------

_LIST_MERGE_KEYS: frozenset[str] = frozenset({
    "errors",
    "findings",
    "scan_results",
})


class PipelineContext(dict[str, Any]):
    """Typed pipeline context with dict-compatible interface.

    Extends ``dict[str, Any]`` so every existing call-site (``context["key"]``,
    ``context.get(...)``, ``context.update(...)``, ``dict(context)``) keeps
    working without changes.  Typed properties provide safe, documented access
    to well-known fields.

    Serialisable via ``dict(ctx)`` for future checkpoint support.
    """

    # -- typed property helpers ------------------------------------------------

    @property
    def request(self) -> Any:
        """``ScanRequest`` that initiated the pipeline."""
        return self.get("request")

    @request.setter
    def request(self, value: Any) -> None:
        self["request"] = value

    @property
    def errors(self) -> list[dict[str, str]]:
        """Accumulated error records from failed steps."""
        return self.setdefault("errors", [])

    @errors.setter
    def errors(self, value: list[dict[str, str]]) -> None:
        self["errors"] = value

    @property
    def scan_results(self) -> list[Any]:
        """Raw ``ScanResult`` objects produced by the scan phase."""
        return self.get("scan_results", [])

    @scan_results.setter
    def scan_results(self, value: list[Any]) -> None:
        self["scan_results"] = value

    @property
    def findings(self) -> list[Any]:
        """Normalised ``Finding`` objects produced by the analyze phase."""
        return self.get("findings", [])

    @findings.setter
    def findings(self, value: list[Any]) -> None:
        self["findings"] = value

    @property
    def reports(self) -> dict[str, Any]:
        """Report payloads keyed by reporter name."""
        return self.get("reports", {})

    @reports.setter
    def reports(self, value: dict[str, Any]) -> None:
        self["reports"] = value

    @property
    def artifacts(self) -> Any:
        """``ArtifactStore`` used for cross-phase DAG orchestration."""
        return self.get("artifacts")

    @artifacts.setter
    def artifacts(self, value: Any) -> None:
        self["artifacts"] = value

    @property
    def scan_started_at(self) -> datetime | None:
        """UTC timestamp injected when the scan begins."""
        return self.get("scan_started_at")

    @scan_started_at.setter
    def scan_started_at(self, value: datetime | None) -> None:
        self["scan_started_at"] = value

    # -- DAG metadata ----------------------------------------------------------

    @property
    def dag_step_status(self) -> dict[str, str]:
        """Per-step terminal status produced by ``PhaseDAGRunner``."""
        return self.get("dag_step_status", {})

    @dag_step_status.setter
    def dag_step_status(self, value: dict[str, str]) -> None:
        self["dag_step_status"] = value

    @property
    def dag_phase_status(self) -> dict[str, str]:
        """Per-phase aggregated status produced by ``PhaseDAGRunner``."""
        return self.get("dag_phase_status", {})

    @dag_phase_status.setter
    def dag_phase_status(self, value: dict[str, str]) -> None:
        self["dag_phase_status"] = value

    @property
    def dag_skip_reasons(self) -> dict[str, str]:
        """Reasons why individual DAG steps were skipped."""
        return self.get("dag_skip_reasons", {})

    @dag_skip_reasons.setter
    def dag_skip_reasons(self, value: dict[str, str]) -> None:
        self["dag_skip_reasons"] = value

    # -- post-scan / AI fields -------------------------------------------------

    @property
    def finding_trends(self) -> dict[str, dict[str, Any]]:
        """Fingerprint trend data added after scan completion."""
        return self.get("finding_trends", {})

    @finding_trends.setter
    def finding_trends(self, value: dict[str, dict[str, Any]]) -> None:
        self["finding_trends"] = value

    @property
    def finding_trend_index_size(self) -> int:
        """Size of the fingerprint trend index after update."""
        return self.get("finding_trend_index_size", 0)

    @finding_trend_index_size.setter
    def finding_trend_index_size(self, value: int) -> None:
        self["finding_trend_index_size"] = value

    @property
    def ai_plan(self) -> dict[str, Any] | None:
        """Serialised AI plan payload."""
        return self.get("ai_plan")

    @ai_plan.setter
    def ai_plan(self, value: dict[str, Any] | None) -> None:
        self["ai_plan"] = value

    @property
    def ai_plan_explain(self) -> str | None:
        """Human-readable AI plan explanation."""
        return self.get("ai_plan_explain")

    @ai_plan_explain.setter
    def ai_plan_explain(self, value: str | None) -> None:
        self["ai_plan_explain"] = value

    # -- snapshot / merge (thread-safety) --------------------------------------

    def deep_snapshot(self) -> PipelineContext:
        """Return a deep copy with shared singleton references preserved.

        ``request`` and ``artifacts`` are shared objects injected once by
        the engine — they are referenced (not copied) so that mutations
        (e.g. ``ArtifactStore.put``) remain visible to all steps.

        All other mutable nested structures (lists, dicts) are recursively
        copied so that modifications in the snapshot cannot affect the
        original.
        """
        shared_keys = ("request", "artifacts")
        saved = {key: self[key] for key in shared_keys if key in self}
        plain = dict(self)
        for key in saved:
            del plain[key]
        snapshot = PipelineContext(copy.deepcopy(plain))
        snapshot.update(saved)
        return snapshot

    def merge_from(
        self,
        update: dict[str, Any],
        *,
        _lock: threading.Lock | None = None,
    ) -> None:
        """Merge *update* into this context with field-aware strategy.

        - Keys in ``_LIST_MERGE_KEYS`` (``errors``, ``findings``,
          ``scan_results``): new items are **appended** to existing lists.
        - ``request`` and ``artifacts`` are **never** overwritten by merge
          (they are injected once by the engine before the pipeline starts).
        - All other keys: **last-write-wins** with a debug log on conflict.
        """
        if _lock is not None:
            _lock.acquire()
        try:
            self._apply_merge(update)
        finally:
            if _lock is not None:
                _lock.release()

    def _apply_merge(self, update: dict[str, Any]) -> None:
        for key, value in update.items():
            if key in ("request", "artifacts"):
                continue

            if key in _LIST_MERGE_KEYS:
                existing = self.get(key)
                if isinstance(existing, list) and isinstance(value, list):
                    existing.extend(value)
                elif isinstance(value, list):
                    self[key] = list(value)
                else:
                    self[key] = value
                continue

            if key in self and self[key] != value:
                _merge_logger.debug(
                    "context_merge_conflict",
                    key=key,
                    old_type=type(self[key]).__name__,
                    new_type=type(value).__name__,
                )

            self[key] = value


StepHandler = Callable[["PipelineContext"], Awaitable["PipelineContext | None"]]
StepCondition = Callable[["PipelineContext"], bool]
