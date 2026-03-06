"""Shared typing aliases for policy internals."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

_IPAddress = IPv4Address | IPv6Address
_IPNetwork = IPv4Network | IPv6Network
