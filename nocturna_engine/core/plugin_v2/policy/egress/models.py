"""Policy and security controls for Plugin Platform v2."""

from __future__ import annotations

from dataclasses import dataclass

from ..types import _IPAddress


@dataclass(frozen=True, slots=True)
class _HostRule:
    raw: str
    host: str | None
    ip: _IPAddress | None
    port: int | None
    protocol: str | None
    wildcard: bool
