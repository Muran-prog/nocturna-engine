"""Scope firewall IP/host matching and canonicalization helpers."""

from __future__ import annotations

from ipaddress import IPv6Address, IPv6Network, ip_address, ip_network

from nocturna_engine.core.security.scope_firewall.types import IpAddress, IpNetwork


def host_matches_rules(host: str, rules: tuple[str, ...]) -> bool:
    for rule in rules:
        if host == rule or host.endswith(f".{rule}"):
            return True
    return False


def canonicalize_ip(ip: IpAddress) -> IpAddress:
    """Collapse IPv6-mapped-IPv4 addresses to their IPv4 form."""
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def ip_in_cidrs(target_ip: IpAddress, rules: tuple[IpNetwork, ...]) -> bool:
    target_ip = canonicalize_ip(target_ip)
    for rule in rules:
        if target_ip.version != rule.version:
            continue
        if target_ip in rule:
            return True
    return False


def ip_matches_host_rules(target_ip: IpAddress, rules: tuple[str, ...]) -> bool:
    target_ip = canonicalize_ip(target_ip)
    for rule in rules:
        try:
            scoped_ip = canonicalize_ip(ip_address(rule))
        except ValueError:
            continue
        if scoped_ip == target_ip:
            return True
    return False


def network_overlaps_cidrs(target_network: IpNetwork, rules: tuple[IpNetwork, ...]) -> bool:
    target_network = canonicalize_network(target_network)
    for rule in rules:
        if target_network.version != rule.version:
            continue
        if target_network.overlaps(rule):
            return True
    return False


def network_in_allowlist(target_network: IpNetwork, allowlist_cidrs: tuple[IpNetwork, ...]) -> bool:
    target_network = canonicalize_network(target_network)
    for rule in allowlist_cidrs:
        if target_network.version != rule.version:
            continue
        if target_network.subnet_of(rule):
            return True
    return False


def canonicalize_network(network: IpNetwork) -> IpNetwork:
    """Collapse IPv6-mapped-IPv4 networks to their IPv4 form."""
    if isinstance(network, IPv6Network):
        addr = network.network_address
        if isinstance(addr, IPv6Address) and addr.ipv4_mapped is not None:
            prefix = network.prefixlen
            if prefix >= 96:
                return ip_network(f"{addr.ipv4_mapped}/{prefix - 96}", strict=False)
    return network
