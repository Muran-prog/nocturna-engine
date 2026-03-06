"""Scope firewall decision and normalized target models."""

from __future__ import annotations

from dataclasses import dataclass

from nocturna_engine.core.security.scope_firewall.types import IpAddress, IpNetwork


@dataclass(frozen=True, slots=True)
class ScopeFirewallDecision:
    """Decision returned by scope firewall validation."""

    allowed: bool
    reason: str | None = None
    reason_code: str | None = None
    normalized_target: str | None = None


@dataclass(frozen=True, slots=True)
class _NormalizedTarget:
    """Internal normalized target representation."""

    kind: str
    value: str
    ip: IpAddress | None = None
    network: IpNetwork | None = None

