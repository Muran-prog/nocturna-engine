"""Scope firewall factory methods (from_runtime, from_mapping)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.core.security.scope_firewall.constants import _RULE_KEYS

from nocturna_engine.core.security.scope_firewall.firewall._normalization import (
    normalize_cidr_rules,
    normalize_host_rules,
)


class ScopeFirewallFactory:
    """Mixin providing factory classmethods for ScopeFirewall construction."""

    @classmethod
    def from_runtime(
        cls,
        *,
        config: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
    ) -> "ScopeFirewallFactory":
        """Build firewall from runtime config and per-request policy overrides."""

        config_rules = cls._extract_rules_payload(config)
        policy_rules = cls._extract_rules_payload(policy)
        merged: dict[str, Any] = dict(config_rules)
        if policy_rules.get("kill_switch"):
            merged["kill_switch"] = True
        for list_key in ("denylist_hosts", "denylist_cidrs"):
            if list_key in policy_rules:
                config_val = config_rules.get(list_key, [])
                policy_val = policy_rules[list_key]
                combined = list(config_val) if isinstance(config_val, (list, tuple)) else []
                if isinstance(policy_val, (list, tuple)):
                    combined.extend(policy_val)
                merged[list_key] = combined
        for list_key in ("allowlist_hosts", "allowlist_cidrs"):
            if list_key in policy_rules:
                merged[list_key] = policy_rules[list_key]
        return cls.from_mapping(merged)

    @classmethod
    def from_mapping(cls, rules: Mapping[str, Any] | None = None) -> "ScopeFirewallFactory":
        """Build firewall from one raw rule mapping."""

        payload = dict(rules or {})
        return cls(
            kill_switch=bool(payload.get("kill_switch", False)),
            allowlist_hosts=normalize_host_rules(payload.get("allowlist_hosts")),
            allowlist_cidrs=normalize_cidr_rules(payload.get("allowlist_cidrs")),
            denylist_hosts=normalize_host_rules(payload.get("denylist_hosts")),
            denylist_cidrs=normalize_cidr_rules(payload.get("denylist_cidrs")),
        )

    @staticmethod
    def _extract_rules_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            return {}

        if all(key in _RULE_KEYS for key in payload):
            return dict(payload)

        nested_security = payload.get("security")
        if isinstance(nested_security, Mapping):
            scope_firewall = nested_security.get("scope_firewall")
            if isinstance(scope_firewall, Mapping):
                return dict(scope_firewall)

        nested = payload.get("scope_firewall")
        if isinstance(nested, Mapping):
            return dict(nested)

        return {key: payload[key] for key in _RULE_KEYS if key in payload}
