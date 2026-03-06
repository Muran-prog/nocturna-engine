"""Shared state models for v2 single-tool execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ToolPreflightState:
    """Preflight artifacts required for tool runtime execution."""

    registration: Any
    policy: Any
    policy_decision: Any
    adapter: Any
    cache_key: str | None
