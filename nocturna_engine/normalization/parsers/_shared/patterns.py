"""Canonical CVE / CWE regex patterns and extraction helpers.

Every parser that needs CVE or CWE extraction MUST import from here
instead of defining its own copy.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Compiled patterns (public — importable by parsers that need the raw object,
# e.g. for ``finditer`` with named groups).
# ---------------------------------------------------------------------------

CVE_PATTERN: re.Pattern[str] = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
"""Matches CVE identifiers like ``CVE-2024-12345``."""

CWE_PATTERN: re.Pattern[str] = re.compile(r"CWE-(\d+)", re.IGNORECASE)
"""Matches CWE identifiers, capturing the numeric ID in group 1."""


# ---------------------------------------------------------------------------
# Accessor helpers — cover every current use-case so callers never need to
# interact with the compiled objects directly.
# ---------------------------------------------------------------------------


def extract_cves(text: str) -> list[str]:
    """Return **sorted unique** CVE identifiers found in *text* (uppercase).

    Used by ``xml_junit`` and ``xml_generic`` parsers.
    """
    return sorted({m.upper() for m in CVE_PATTERN.findall(text)})


def extract_first_cve(text: str) -> str | None:
    """Return the first CVE identifier found in *text* (uppercase), or ``None``.

    Used by ``xml_nmap`` parser.
    """
    match = CVE_PATTERN.search(text)
    if match:
        return match.group(0).upper()
    return None


def extract_cwe(text: str) -> str | None:
    """Extract the first CWE identifier from *text*.

    Returns a normalized string like ``"CWE-79"``, or ``None`` if no CWE
    reference is found.
    """
    match = CWE_PATTERN.search(text)
    if match:
        return f"CWE-{match.group(1)}"
    return None


def extract_cwes(text: str) -> list[str]:
    """Return **sorted unique** CWE identifiers found in *text* (e.g. ``["CWE-22", "CWE-79"]``).

    Used by ``xml_junit`` parser.
    """
    return sorted({f"CWE-{m}" for m in CWE_PATTERN.findall(text)})
