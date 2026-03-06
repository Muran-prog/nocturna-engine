"""SARIF URI sanitisation and target extraction."""

from __future__ import annotations

import posixpath
from typing import Any
from urllib.parse import urlparse


def _sanitize_uri(uri: str) -> str | None:
    """Sanitize a SARIF artifact URI to prevent path traversal.

    Returns the cleaned path, or ``None`` if the URI is unsafe and cannot
    be reasonably neutralised (e.g. ``file://`` scheme pointing outside the
    project).
    """
    stripped = uri.strip()
    if not stripped:
        return None

    # Reject dangerous schemes (file://, ftp://, etc.).
    parsed = urlparse(stripped)
    if parsed.scheme and parsed.scheme.lower() not in ("", "https", "http", "sarif"):
        return None

    # For scheme-less paths, normalise and reject traversal above root.
    path = parsed.path if parsed.scheme else stripped
    normalised = posixpath.normpath(path)

    # normpath keeps leading ".." segments; reject them.
    if normalised.startswith("..") or normalised.startswith("/"):
        # Absolute paths inside SARIF are acceptable as-is after normpath,
        # but relative paths escaping the project root are not.
        if not normalised.startswith("/"):
            return None

    return normalised


def extract_target(result: dict[str, Any], *, fallback: str) -> str:
    """Extract target from SARIF result locations."""
    locations = result.get("locations")
    if isinstance(locations, list):
        for location in locations:
            if not isinstance(location, dict):
                continue
            physical = location.get("physicalLocation")
            if isinstance(physical, dict):
                artifact = physical.get("artifactLocation")
                if isinstance(artifact, dict):
                    uri = artifact.get("uri", "")
                    if uri:
                        sanitized = _sanitize_uri(str(uri))
                        if sanitized is not None:
                            return sanitized

    return fallback
