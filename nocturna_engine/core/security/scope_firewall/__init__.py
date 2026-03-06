"""Core scope firewall for host/IP/CIDR enforcement."""

from __future__ import annotations

from nocturna_engine.core.security.scope_firewall.constants import (
    SCOPE_REASON_DENIED,
    SCOPE_REASON_INVALID_TARGET,
    SCOPE_REASON_KILL_SWITCH,
)
from nocturna_engine.core.security.scope_firewall.firewall import ScopeFirewall
from nocturna_engine.core.security.scope_firewall.models import ScopeFirewallDecision

__all__ = [
    "SCOPE_REASON_DENIED",
    "SCOPE_REASON_INVALID_TARGET",
    "SCOPE_REASON_KILL_SWITCH",
    "ScopeFirewall",
    "ScopeFirewallDecision",
]
