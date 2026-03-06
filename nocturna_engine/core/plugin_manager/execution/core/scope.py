"""Scope and target helpers for core execution."""

from __future__ import annotations

from collections.abc import Mapping
from ipaddress import ip_address, ip_network
from typing import Any

from nocturna_engine.core.security import ScopeFirewall
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.target import Target


class PluginScopeValidationMixin:
    def _build_scope_firewall(self, *, request: ScanRequest) -> ScopeFirewall:
        return ScopeFirewall.from_runtime(
            config=self._config,
            policy=self._resolve_scope_firewall_policy(request),
        )

    @staticmethod
    def _resolve_scope_firewall_policy(request: ScanRequest) -> Mapping[str, Any] | None:
        policy_payload = request.metadata.get("scope_firewall")
        if isinstance(policy_payload, Mapping):
            return policy_payload
        return None

    @staticmethod
    def _target_label(target: Target) -> str:
        if target.domain is not None:
            return target.domain
        if target.ip is not None:
            return str(target.ip)
        return "unknown_target"

    @classmethod
    def _is_target_within_scope(cls, target: Target) -> bool:
        if not target.scope:
            return True

        target_domain = target.domain.lower() if target.domain is not None else None
        target_ip = target.ip

        for raw_entry in target.scope:
            entry = raw_entry.strip().lower()
            if not entry:
                continue

            if "/" in entry:
                try:
                    network = ip_network(entry, strict=False)
                except ValueError:
                    continue
                if target_ip is not None and target_ip in network:
                    return True
                continue

            try:
                scoped_ip = ip_address(entry)
            except ValueError:
                if target_domain is not None and (
                    target_domain == entry or target_domain.endswith(f".{entry}")
                ):
                    return True
            else:
                if target_ip is not None and target_ip == scoped_ip:
                    return True

        return False
