"""AI target parsing helpers for Nocturna Engine."""

from __future__ import annotations

import re
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from nocturna_engine.models.target import DOMAIN_PATTERN, Target

from .constants import _WINDOWS_DRIVE_PATTERN, _WINDOWS_UNC_PATTERN

_DOMAIN_RE = re.compile(DOMAIN_PATTERN)

class _EngineAITargetingMixin:
    @staticmethod
    def _build_target_from_ai_input(raw_target: str) -> Target:
        candidate = raw_target.strip()
        if not candidate:
            raise ValueError("AI target cannot be empty.")

        explicit_url_host = _EngineAITargetingMixin._extract_explicit_url_host(candidate)
        if explicit_url_host is not None:
            explicit_url_target = _EngineAITargetingMixin._build_host_target(explicit_url_host)
            if explicit_url_target is not None:
                return explicit_url_target

        stripped_ip_candidate = candidate
        if stripped_ip_candidate.startswith("[") and stripped_ip_candidate.endswith("]"):
            stripped_ip_candidate = stripped_ip_candidate[1:-1]

        try:
            ip_value = ip_address(stripped_ip_candidate)
            return Target(ip=ip_value)
        except ValueError:
            pass

        try:
            return Target(domain=candidate.lower())
        except ValueError:
            pass

        host_candidate = _EngineAITargetingMixin._extract_host_from_domain_like_target(candidate)
        if host_candidate is not None:
            host_target = _EngineAITargetingMixin._build_host_target(host_candidate)
            if host_target is not None:
                return host_target

        if _EngineAITargetingMixin._looks_like_local_path(candidate):
            resolved = Path(candidate).expanduser().resolve(strict=False)
            return Target(
                domain="local.scan",
                metadata={"target_path": str(resolved)},
            )

        raise ValueError("AI target must be a valid URL, IP, domain, or explicit local path.")

    @staticmethod
    def _build_host_target(host: str) -> Target | None:
        normalized_host = host.strip().lower()
        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            normalized_host = normalized_host[1:-1]
        try:
            return Target(ip=ip_address(normalized_host))
        except ValueError:
            try:
                return Target(domain=normalized_host)
            except ValueError:
                return None

    @staticmethod
    def _extract_explicit_url_host(candidate: str) -> str | None:
        if "://" in candidate:
            parsed = urlparse(candidate)
            if parsed.netloc and parsed.hostname and len(parsed.scheme) > 1:
                return parsed.hostname.lower()
        return None

    @staticmethod
    def _extract_host_from_domain_like_target(candidate: str) -> str | None:
        if _WINDOWS_DRIVE_PATTERN.match(candidate) or _WINDOWS_UNC_PATTERN.match(candidate):
            return None
        if "\\" in candidate or candidate.startswith(("./", "../", "/", "~", ".\\", "..\\" , "\\\\")):
            return None
        if any(marker in candidate for marker in ("/", "?", "#", ":")):
            parsed = urlparse(f"https://{candidate}")
            hostname = parsed.hostname
            if hostname and _DOMAIN_RE.fullmatch(hostname.lower()):
                return hostname.lower()
        return None

    @staticmethod
    def _looks_like_local_path(candidate: str) -> bool:
        if _WINDOWS_DRIVE_PATTERN.match(candidate) or _WINDOWS_UNC_PATTERN.match(candidate):
            return True
        if candidate.startswith(("./", "../", "/", "~", ".\\", "..\\", "\\\\")):
            return True
        # Bare relative path containing a separator (e.g. "foo/bar") that was
        # not recognised as a domain or URL by earlier pipeline stages.
        if "/" in candidate or "\\" in candidate:
            return True
        return False
