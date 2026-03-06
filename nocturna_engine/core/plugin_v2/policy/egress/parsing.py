"""Policy and security controls for Plugin Platform v2."""

from __future__ import annotations

from ipaddress import ip_network
from urllib.parse import urlsplit

from ..types import _IPNetwork
from .models import _HostRule
from .normalization import normalize_host, normalize_ip, normalize_protocol, try_normalize_port


def parse_host_rules(entries: tuple[str, ...]) -> tuple[_HostRule, ...]:
    parsed: list[_HostRule] = []
    for entry in entries:
        rule = parse_host_rule(entry)
        if rule is not None:
            parsed.append(rule)
    return tuple(parsed)


def parse_cidrs(entries: tuple[str, ...]) -> tuple[_IPNetwork, ...]:
    return tuple(ip_network(entry, strict=False) for entry in entries)


def parse_host_rule(raw_rule: str) -> _HostRule | None:
    candidate = str(raw_rule).strip().lower()
    if not candidate:
        return None

    protocol: str | None = None
    host: str | None = None
    port: int | None = None
    parse_target = candidate
    if "://" not in parse_target:
        parse_target = f"//{parse_target}"

    try:
        parsed = urlsplit(parse_target)
    except Exception:
        parsed = None

    if parsed is not None:
        protocol = normalize_protocol(parsed.scheme)
        host = normalize_host(parsed.hostname)
        try:
            port = try_normalize_port(parsed.port)
        except ValueError:
            port = None

    if host is None:
        host = normalize_host(candidate)
    if host is None:
        return None

    wildcard = False
    if host.startswith("*."):
        wildcard = True
        host = host[2:]
        if not host:
            return None

    ip_value = normalize_ip(host)
    if ip_value is not None:
        wildcard = False

    return _HostRule(
        raw=raw_rule,
        host=host,
        ip=ip_value,
        port=port,
        protocol=protocol,
        wildcard=wildcard,
    )
