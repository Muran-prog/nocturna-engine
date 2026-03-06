"""Helper functions for extracting structured data from JUnit XML failures."""

from __future__ import annotations

from nocturna_engine.normalization.parsers._shared.patterns import (
    extract_cves as _extract_cves,
    extract_cwes as _extract_cwes,
)
from nocturna_engine.normalization.parsers.xml_junit._constants import (
    _FILE_PATH_RE,
    _RESOURCE_RE,
    _SEVERITY_RE,
    _URL_RE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_severity_token(
    classname: str,
    failure_message: str,
    failure_text: str,
) -> str | None:
    """Try to extract a severity keyword from classname, message, or text."""
    for source in (classname, failure_message, failure_text):
        match = _SEVERITY_RE.search(source)
        if match:
            return match.group(1)
    return None


def _extract_target(
    failure_text: str,
    classname: str,
    target_hint: str | None,
) -> str:
    """Extract a target identifier from failure text with multiple fallbacks."""
    # 1) URL
    url_match = _URL_RE.search(failure_text)
    if url_match:
        return url_match.group(0)

    # 2) Resource: ... line
    resource_match = _RESOURCE_RE.search(failure_text)
    if resource_match:
        return resource_match.group(1).strip()

    # 3) File path (/path or /path:line)
    path_match = _FILE_PATH_RE.search(failure_text)
    if path_match:
        return path_match.group(1)

    # 4) Classname fallback
    if classname:
        return classname

    # 5) Config target_hint
    return target_hint or "unknown"


# _extract_cves and _extract_cwes are imported from _shared.patterns above.
