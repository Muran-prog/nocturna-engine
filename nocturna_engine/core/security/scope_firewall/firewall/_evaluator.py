"""Core scope firewall evaluator implementation."""

from __future__ import annotations

from nocturna_engine.core.security.scope_firewall.constants import (
    SCOPE_REASON_DENIED,
    SCOPE_REASON_INVALID_TARGET,
    SCOPE_REASON_KILL_SWITCH,
)
from nocturna_engine.core.security.scope_firewall.models import ScopeFirewallDecision
from nocturna_engine.core.security.scope_firewall.types import IpAddress, IpNetwork
from nocturna_engine.models.target import Target

from nocturna_engine.core.security.scope_firewall.firewall._factory import ScopeFirewallFactory
from nocturna_engine.core.security.scope_firewall.firewall._matching import (
    host_matches_rules,
    ip_in_cidrs,
    ip_matches_host_rules,
    network_in_allowlist,
    network_overlaps_cidrs,
)
from nocturna_engine.core.security.scope_firewall.firewall._normalization import normalize_target


class ScopeFirewall(ScopeFirewallFactory):
    """Evaluate host/IP/CIDR targets against runtime scope policy."""

    __slots__ = ("kill_switch", "allowlist_hosts", "allowlist_cidrs", "denylist_hosts", "denylist_cidrs", "_frozen")

    def __init__(
        self,
        *,
        kill_switch: bool = False,
        allowlist_hosts: tuple[str, ...] = (),
        allowlist_cidrs: tuple[IpNetwork, ...] = (),
        denylist_hosts: tuple[str, ...] = (),
        denylist_cidrs: tuple[IpNetwork, ...] = (),
    ) -> None:
        object.__setattr__(self, "kill_switch", bool(kill_switch))
        object.__setattr__(self, "allowlist_hosts", allowlist_hosts)
        object.__setattr__(self, "allowlist_cidrs", allowlist_cidrs)
        object.__setattr__(self, "denylist_hosts", denylist_hosts)
        object.__setattr__(self, "denylist_cidrs", denylist_cidrs)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError(f"ScopeFirewall is immutable: cannot set '{name}'")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"ScopeFirewall is immutable: cannot delete '{name}'")

    def evaluate_target(self, target: Target | str | IpAddress | IpNetwork) -> ScopeFirewallDecision:
        """Evaluate one host/IP/CIDR target against configured rules."""

        if self.kill_switch:
            normalized = normalize_target(target)
            return ScopeFirewallDecision(
                allowed=False,
                reason="scope_firewall_kill_switch_enabled",
                reason_code=SCOPE_REASON_KILL_SWITCH,
                normalized_target=normalized.value if normalized is not None else None,
            )

        normalized = normalize_target(target)
        if normalized is None:
            return ScopeFirewallDecision(
                allowed=False,
                reason="scope_firewall_invalid_target",
                reason_code=SCOPE_REASON_INVALID_TARGET,
            )

        has_allowlist = bool(self.allowlist_hosts or self.allowlist_cidrs)
        if normalized.kind == "host":
            host = normalized.value
            if host_matches_rules(host, self.denylist_hosts):
                return ScopeFirewallDecision(
                    allowed=False,
                    reason="scope_firewall_denylist_host_match",
                    reason_code=SCOPE_REASON_DENIED,
                    normalized_target=host,
                )
            if has_allowlist and not host_matches_rules(host, self.allowlist_hosts):
                return ScopeFirewallDecision(
                    allowed=False,
                    reason="scope_firewall_target_not_in_allowlist",
                    reason_code=SCOPE_REASON_DENIED,
                    normalized_target=host,
                )
            return ScopeFirewallDecision(allowed=True, normalized_target=host)

        if normalized.kind == "ip" and normalized.ip is not None:
            target_ip = normalized.ip
            if ip_in_cidrs(target_ip, self.denylist_cidrs) or ip_matches_host_rules(
                target_ip, self.denylist_hosts
            ):
                return ScopeFirewallDecision(
                    allowed=False,
                    reason="scope_firewall_denylist_cidr_match",
                    reason_code=SCOPE_REASON_DENIED,
                    normalized_target=normalized.value,
                )
            if has_allowlist and not (
                ip_in_cidrs(target_ip, self.allowlist_cidrs)
                or ip_matches_host_rules(target_ip, self.allowlist_hosts)
            ):
                return ScopeFirewallDecision(
                    allowed=False,
                    reason="scope_firewall_target_not_in_allowlist",
                    reason_code=SCOPE_REASON_DENIED,
                    normalized_target=normalized.value,
                )
            return ScopeFirewallDecision(allowed=True, normalized_target=normalized.value)

        if normalized.kind == "cidr" and normalized.network is not None:
            target_network = normalized.network
            if network_overlaps_cidrs(target_network, self.denylist_cidrs):
                return ScopeFirewallDecision(
                    allowed=False,
                    reason="scope_firewall_denylist_cidr_match",
                    reason_code=SCOPE_REASON_DENIED,
                    normalized_target=normalized.value,
                )
            if has_allowlist and not network_in_allowlist(target_network, self.allowlist_cidrs):
                return ScopeFirewallDecision(
                    allowed=False,
                    reason="scope_firewall_target_not_in_allowlist",
                    reason_code=SCOPE_REASON_DENIED,
                    normalized_target=normalized.value,
                )
            return ScopeFirewallDecision(allowed=True, normalized_target=normalized.value)

        return ScopeFirewallDecision(
            allowed=False,
            reason="scope_firewall_invalid_target",
            reason_code=SCOPE_REASON_INVALID_TARGET,
        )
