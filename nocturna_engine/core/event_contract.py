"""Unified event contract and bridge helpers for core and plugin v2."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_EVENT_ALIASES: dict[str, tuple[str, ...]] = {
    "on_scan_started": ("scan.started",),
    "on_scan_finished": ("scan.finished",),
    "on_phase_started": ("phase.started",),
    "on_phase_finished": ("phase.finished",),
    "on_phase_failed": ("phase.failed",),
    "on_tool_initialized": ("tool.initialized",),
    "on_tool_started": ("tool.started",),
    "on_tool_finished": ("tool.finished",),
    "on_tool_error": ("tool.error",),
    "on_scope_denied": ("scope.denied",),
    "on_policy_invalid": ("policy.invalid",),
    "on_ai_plan_rejected": ("ai.plan_rejected",),
    "on_finding_detected": ("finding.detected",),
    "on_raw_finding_detected": ("finding.detected.raw",),
    "scan_started": ("scan.started",),
    "scan_completed": ("scan.completed",),
    "tool_error": ("tool.error",),
    "finding_detected": ("finding.detected",),
}


def build_reverse_aliases(alias_map: Mapping[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
    """Build reverse alias lookup for bidirectional compatibility."""

    reverse: dict[str, set[str]] = {}
    for name, aliases in alias_map.items():
        for alias in aliases:
            reverse.setdefault(alias, set()).add(name)
    return {key: tuple(sorted(values)) for key, values in reverse.items()}


class EventV2(BaseModel):
    """Typed event payload contract v2."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_version: str = Field(default="2.0.0")
    event_type: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    emitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_legacy_payload(self) -> dict[str, Any]:
        """Project typed event into payload compatible with legacy handlers."""

        return {
            **self.payload,
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "emitted_at": self.emitted_at.isoformat(),
        }


def normalize_event_payload(event_name: str, payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize payload to v2-compatible shape while preserving legacy keys."""

    normalized = dict(payload or {})
    normalized.setdefault("schema_version", "2.0.0")
    normalized.setdefault("event_type", event_name)
    normalized.setdefault("emitted_at", datetime.now(UTC).isoformat())
    return normalized
