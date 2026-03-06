"""Scope firewall IP typing aliases."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

IpAddress = IPv4Address | IPv6Address
IpNetwork = IPv4Network | IPv6Network

