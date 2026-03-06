"""Backward-compatible event contract exports for plugin platform v2."""

from __future__ import annotations

from nocturna_engine.core.event_contract import (
    DEFAULT_EVENT_ALIASES,
    EventV2,
    build_reverse_aliases,
    normalize_event_payload,
)

__all__ = [
    "DEFAULT_EVENT_ALIASES",
    "EventV2",
    "build_reverse_aliases",
    "normalize_event_payload",
]
