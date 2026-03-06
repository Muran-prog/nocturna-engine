"""Scope firewall target/rule normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Any

from nocturna_engine.core.security.scope_firewall.constants import _LABEL_PATTERN
from nocturna_engine.core.security.scope_firewall.models import _NormalizedTarget
from nocturna_engine.core.security.scope_firewall.types import IpNetwork

from nocturna_engine.core.security.scope_firewall.firewall._matching import canonicalize_ip


def normalize_host_rules(raw_rules: Any) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for candidate in iter_rule_values(raw_rules):
        host = normalize_host(candidate)
        if host is None or host in seen:
            continue
        seen.add(host)
        normalized.append(host)
    return tuple(normalized)


def normalize_cidr_rules(raw_rules: Any) -> tuple[IpNetwork, ...]:
    normalized: list[IpNetwork] = []
    seen: set[str] = set()
    for candidate in iter_rule_values(raw_rules):
        network = coerce_network(candidate)
        if network is None:
            continue
        encoded = str(network)
        if encoded in seen:
            continue
        seen.add(encoded)
        normalized.append(network)
    return tuple(normalized)


def iter_rule_values(raw_rules: Any) -> Iterable[str]:
    if raw_rules is None:
        return ()
    if isinstance(raw_rules, str):
        return (raw_rules,)
    if isinstance(raw_rules, Iterable):
        return (str(item) for item in raw_rules if item is not None)
    return ()


def normalize_target(target: Any) -> _NormalizedTarget | None:
    # Import here to avoid circular dependency with Target model
    from nocturna_engine.models.target import Target

    if isinstance(target, Target):
        if target.domain is not None:
            normalized_host = normalize_host(target.domain)
            if normalized_host is None:
                return None
            return _NormalizedTarget(kind="host", value=normalized_host)
        if target.ip is not None:
            canonicalized = canonicalize_ip(target.ip)
            return _NormalizedTarget(kind="ip", value=str(canonicalized), ip=canonicalized)
        return None

    if isinstance(target, (IPv4Address, IPv6Address)):
        canonicalized = canonicalize_ip(target)
        return _NormalizedTarget(kind="ip", value=str(canonicalized), ip=canonicalized)

    if isinstance(target, (IPv4Network, IPv6Network)):
        return _NormalizedTarget(kind="cidr", value=str(target), network=target)

    candidate = str(target).strip()
    if not candidate:
        return None

    if "/" in candidate:
        network = coerce_network(candidate)
        if network is None:
            return None
        return _NormalizedTarget(kind="cidr", value=str(network), network=network)

    try:
        parsed_ip = ip_address(candidate)
    except ValueError:
        normalized_host = normalize_host(candidate)
        if normalized_host is None:
            return None
        return _NormalizedTarget(kind="host", value=normalized_host)
    parsed_ip = canonicalize_ip(parsed_ip)
    return _NormalizedTarget(kind="ip", value=str(parsed_ip), ip=parsed_ip)


def coerce_network(value: str) -> IpNetwork | None:
    candidate = str(value).strip()
    if not candidate:
        return None
    if "/" not in candidate:
        try:
            host_ip = ip_address(candidate)
        except ValueError:
            return None
        if isinstance(host_ip, IPv4Address):
            candidate = f"{host_ip}/32"
        else:
            candidate = f"{host_ip}/128"
    try:
        return ip_network(candidate, strict=False)
    except ValueError:
        return None


def normalize_host(value: str) -> str | None:
    candidate = str(value).strip().lower().rstrip(".")
    if not candidate:
        return None
    try:
        encoded = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    normalized = encoded.strip().lower().rstrip(".")
    if not normalized or len(normalized) > 253:
        return None
    labels = normalized.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return None
        if _LABEL_PATTERN.fullmatch(label) is None:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
    return normalized
