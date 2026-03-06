"""Policy and security controls for Plugin Platform v2."""

from __future__ import annotations

from typing import Any

from ..constants import (
    POLICY_REASON_DENIED_EGRESS_CIDR,
    POLICY_REASON_DENIED_EGRESS_HOST,
    POLICY_REASON_DENIED_EGRESS_PORT,
    POLICY_REASON_DENIED_EGRESS_PROTOCOL,
    _EGRESS_REASON_MAP,
)
from ..models import EgressDecision, EgressEndpoint, PluginPolicy
from ..types import _IPAddress, _IPNetwork
from .matching import first_cidr_match, render_rule_set, rule_matches_endpoint
from .models import _HostRule
from .normalization import (
    DEFAULT_PORTS,
    normalize_host,
    normalize_ip,
    normalize_protocol,
    split_endpoint_text,
    try_normalize_port,
)
from .parsing import parse_cidrs, parse_host_rule, parse_host_rules


class EgressPolicyEvaluator:
    """Evaluate endpoint egress permissions using allow/deny policy rules."""

    _DEFAULT_PORTS: dict[str, int] = dict(DEFAULT_PORTS)

    def __init__(self, policy: PluginPolicy) -> None:
        self._policy = policy
        self._allow_host_rules = self._parse_host_rules(policy.egress_allow_hosts)
        self._deny_host_rules = self._parse_host_rules(policy.egress_deny_hosts)
        self._allow_cidrs = self._parse_cidrs(policy.egress_allow_cidrs)
        self._deny_cidrs = self._parse_cidrs(policy.egress_deny_cidrs)
        self._allow_ports = set(policy.egress_allow_ports)
        self._deny_ports = set(policy.egress_deny_ports)
        self._allow_protocols = set(policy.egress_allow_protocols)
        self._deny_protocols = set(policy.egress_deny_protocols)

    @property
    def is_configured(self) -> bool:
        """Return True when evaluator has active policy constraints."""

        return self._policy.has_egress_rules()

    def evaluate(
        self,
        *,
        endpoint: EgressEndpoint | None = None,
        endpoint_text: str | None = None,
        host: str | None = None,
        ip: str | _IPAddress | None = None,
        port: int | str | None = None,
        protocol: str | None = None,
        source: str | None = None,
    ) -> EgressDecision:
        """Evaluate one endpoint against egress rules."""

        normalized = endpoint or self.normalize_endpoint(
            endpoint_text=endpoint_text,
            host=host,
            ip=ip,
            port=port,
            protocol=protocol,
            source=source,
        )
        if not self.is_configured:
            return EgressDecision(allowed=True, endpoint=normalized)
        return self._evaluate_endpoint(normalized)

    @classmethod
    def normalize_endpoint(
        cls,
        *,
        endpoint_text: str | None = None,
        host: str | None = None,
        ip: str | _IPAddress | None = None,
        port: int | str | None = None,
        protocol: str | None = None,
        source: str | None = None,
    ) -> EgressEndpoint:
        """Normalize endpoint attributes to host/ip/port/protocol tuple."""

        parsed_host: str | None = None
        parsed_ip: _IPAddress | None = None
        parsed_port: int | None = None
        parsed_protocol: str | None = None

        if endpoint_text:
            parsed_host, parsed_ip, parsed_port, parsed_protocol = cls._split_endpoint_text(endpoint_text)

        normalized_host = cls._normalize_host(host) or parsed_host
        normalized_ip = cls._normalize_ip(ip) or parsed_ip
        normalized_protocol = cls._normalize_protocol(protocol) or parsed_protocol
        normalized_port = cls._try_normalize_port(port) if port is not None else parsed_port

        if normalized_ip is None and normalized_host is not None:
            normalized_ip = cls._normalize_ip(normalized_host)
        if normalized_host is None and normalized_ip is not None:
            normalized_host = str(normalized_ip)
        if normalized_port is None and normalized_protocol in cls._DEFAULT_PORTS:
            normalized_port = cls._DEFAULT_PORTS[normalized_protocol]

        return EgressEndpoint(
            host=normalized_host,
            ip=str(normalized_ip) if normalized_ip is not None else None,
            port=normalized_port,
            protocol=normalized_protocol,
            source=source,
        )

    def _evaluate_endpoint(self, endpoint: EgressEndpoint) -> EgressDecision:
        if endpoint.protocol is not None and endpoint.protocol in self._deny_protocols:
            return self._deny(
                endpoint,
                reason_code=POLICY_REASON_DENIED_EGRESS_PROTOCOL,
                policy_rule=endpoint.protocol,
                matcher="deny_protocols",
            )

        if endpoint.port is not None and endpoint.port in self._deny_ports:
            return self._deny(
                endpoint,
                reason_code=POLICY_REASON_DENIED_EGRESS_PORT,
                policy_rule=str(endpoint.port),
                matcher="deny_ports",
            )

        for rule in self._deny_host_rules:
            if not self._rule_matches_endpoint(rule, endpoint):
                continue
            reason_code = POLICY_REASON_DENIED_EGRESS_HOST
            if rule.protocol is not None:
                reason_code = POLICY_REASON_DENIED_EGRESS_PROTOCOL
            elif rule.port is not None:
                reason_code = POLICY_REASON_DENIED_EGRESS_PORT
            return self._deny(
                endpoint,
                reason_code=reason_code,
                policy_rule=rule.raw,
                matcher="deny_hosts",
            )

        cidr_match = self._first_cidr_match(endpoint, self._deny_cidrs)
        if cidr_match is not None:
            return self._deny(
                endpoint,
                reason_code=POLICY_REASON_DENIED_EGRESS_CIDR,
                policy_rule=str(cidr_match),
                matcher="deny_cidrs",
            )

        if self._allow_protocols and (endpoint.protocol is None or endpoint.protocol not in self._allow_protocols):
            return self._deny(
                endpoint,
                reason_code=POLICY_REASON_DENIED_EGRESS_PROTOCOL,
                policy_rule=self._render_rule_set(sorted(self._allow_protocols)),
                matcher="allow_protocols",
            )

        if self._allow_ports and (endpoint.port is None or endpoint.port not in self._allow_ports):
            return self._deny(
                endpoint,
                reason_code=POLICY_REASON_DENIED_EGRESS_PORT,
                policy_rule=self._render_rule_set([str(value) for value in sorted(self._allow_ports)]),
                matcher="allow_ports",
            )

        if self._allow_host_rules or self._allow_cidrs:
            for rule in self._allow_host_rules:
                if self._rule_matches_endpoint(rule, endpoint):
                    return EgressDecision(allowed=True, endpoint=endpoint)
            allow_cidr_match = self._first_cidr_match(endpoint, self._allow_cidrs)
            if allow_cidr_match is not None:
                return EgressDecision(allowed=True, endpoint=endpoint)
            if endpoint.ip is not None and self._allow_cidrs and not self._allow_host_rules:
                return self._deny(
                    endpoint,
                    reason_code=POLICY_REASON_DENIED_EGRESS_CIDR,
                    policy_rule=self._render_rule_set([str(item) for item in self._allow_cidrs]),
                    matcher="allow_cidrs",
                )
            return self._deny(
                endpoint,
                reason_code=POLICY_REASON_DENIED_EGRESS_HOST,
                policy_rule=self._render_rule_set([rule.raw for rule in self._allow_host_rules]),
                matcher="allow_hosts",
            )

        if self._policy.default_egress_action == "deny":
            reason_code = (
                POLICY_REASON_DENIED_EGRESS_CIDR
                if endpoint.ip is not None and endpoint.host is None
                else POLICY_REASON_DENIED_EGRESS_HOST
            )
            return self._deny(
                endpoint,
                reason_code=reason_code,
                policy_rule="default_egress_action=deny",
                matcher="default_action",
            )

        return EgressDecision(allowed=True, endpoint=endpoint)

    def _deny(
        self,
        endpoint: EgressEndpoint,
        *,
        reason_code: str,
        policy_rule: str,
        matcher: str,
    ) -> EgressDecision:
        return EgressDecision(
            allowed=False,
            reason=_EGRESS_REASON_MAP.get(reason_code, "policy_denied:egress"),
            reason_code=reason_code,
            policy_rule=policy_rule,
            matcher=matcher,
            endpoint=endpoint,
        )

    @classmethod
    def _parse_host_rules(cls, entries: tuple[str, ...]) -> tuple[_HostRule, ...]:
        return parse_host_rules(entries)

    @staticmethod
    def _parse_cidrs(entries: tuple[str, ...]) -> tuple[_IPNetwork, ...]:
        return parse_cidrs(entries)

    @classmethod
    def _parse_host_rule(cls, raw_rule: str) -> _HostRule | None:
        return parse_host_rule(raw_rule)

    @classmethod
    def _split_endpoint_text(
        cls,
        raw_endpoint: str,
    ) -> tuple[str | None, _IPAddress | None, int | None, str | None]:
        return split_endpoint_text(raw_endpoint)

    @classmethod
    def _rule_matches_endpoint(cls, rule: _HostRule, endpoint: EgressEndpoint) -> bool:
        return rule_matches_endpoint(rule, endpoint)

    @staticmethod
    def _first_cidr_match(endpoint: EgressEndpoint, networks: tuple[_IPNetwork, ...]) -> _IPNetwork | None:
        return first_cidr_match(endpoint, networks)

    @staticmethod
    def _render_rule_set(values: list[str]) -> str:
        return render_rule_set(values)

    @staticmethod
    def _normalize_host(value: Any) -> str | None:
        return normalize_host(value)

    @staticmethod
    def _normalize_protocol(value: Any) -> str | None:
        return normalize_protocol(value)

    @staticmethod
    def _normalize_ip(value: Any) -> _IPAddress | None:
        return normalize_ip(value)

    @classmethod
    def _try_normalize_port(cls, value: Any) -> int | None:
        return try_normalize_port(value)
