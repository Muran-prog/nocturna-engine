"""Policy and security controls for Plugin Platform v2."""

from __future__ import annotations

from ipaddress import IPv6Address, ip_address

from ..models import EgressEndpoint
from ..types import _IPNetwork
from .models import _HostRule


def rule_matches_endpoint(rule: _HostRule, endpoint: EgressEndpoint) -> bool:
    if rule.protocol is not None and endpoint.protocol != rule.protocol:
        return False
    if rule.port is not None and endpoint.port != rule.port:
        return False

    if rule.ip is not None:
        return endpoint.ip == str(rule.ip)

    if rule.host is None or endpoint.host is None:
        return False

    endpoint_host = endpoint.host
    if endpoint_host == rule.host:
        return True
    if rule.wildcard:
        return endpoint_host.endswith(f".{rule.host}")
    return endpoint_host.endswith(f".{rule.host}")


def first_cidr_match(endpoint: EgressEndpoint, networks: tuple[_IPNetwork, ...]) -> _IPNetwork | None:
    if endpoint.ip is None:
        return None
    try:
        endpoint_ip = ip_address(endpoint.ip)
    except ValueError:
        return None
    if isinstance(endpoint_ip, IPv6Address) and endpoint_ip.ipv4_mapped is not None:
        endpoint_ip = endpoint_ip.ipv4_mapped
    for network in networks:
        if network.version != endpoint_ip.version:
            continue
        if endpoint_ip in network:
            return network
    return None


def render_rule_set(values: list[str]) -> str:
    if not values:
        return "<empty>"
    return ",".join(values)
