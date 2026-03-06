"""Policy and security controls for Plugin Platform v2."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from ..types import _IPAddress

DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
}


def normalize_host(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip().lower().rstrip(".")
    if not candidate:
        return None
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    return candidate or None


def normalize_protocol(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip().lower()
    return candidate or None


def normalize_ip(value: Any) -> _IPAddress | None:
    if value is None:
        return None
    candidate = str(value).strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if not candidate:
        return None
    try:
        return ip_address(candidate)
    except ValueError:
        return None


def try_normalize_port(value: Any) -> int | None:
    if value is None:
        return None
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return None
    if normalized < 1 or normalized > 65535:
        return None
    return normalized


def split_endpoint_text(raw_endpoint: str) -> tuple[str | None, _IPAddress | None, int | None, str | None]:
    text = str(raw_endpoint).strip()
    if not text:
        return None, None, None, None

    parse_target = text if "://" in text or text.startswith("//") else f"//{text}"
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
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
        host = normalize_host(text)

    ip_value = normalize_ip(host)
    if ip_value is None:
        stripped = text
        if stripped.startswith("[") and stripped.endswith("]"):
            stripped = stripped[1:-1]
        ip_value = normalize_ip(stripped)

    if port is None and protocol in DEFAULT_PORTS:
        port = DEFAULT_PORTS[protocol]
    return host, ip_value, port, protocol
