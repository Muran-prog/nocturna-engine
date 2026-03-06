"""Column alias definitions and header matching for generic CSV parsing."""

from __future__ import annotations

# Mapping from common CSV column names to Finding fields.
_COLUMN_ALIASES: dict[str, list[str]] = {
    "title": ["title", "name", "vulnerability", "finding", "rule", "check", "issue"],
    "description": ["description", "detail", "details", "message", "summary", "info"],
    "severity": ["severity", "risk", "priority", "level", "rating", "impact"],
    "target": ["target", "host", "ip", "address", "url", "hostname", "asset", "endpoint"],
    "cwe": ["cwe", "cwe_id", "cwe-id"],
    "cvss": ["cvss", "cvss_score", "cvss-score", "score"],
    "tool": ["tool", "scanner", "source", "plugin"],
}


def _find_column(headers: list[str], aliases: list[str]) -> int | None:
    """Find the index of the first matching column header.

    Args:
        headers: Lowercase, stripped column headers.
        aliases: Aliases to match against.

    Returns:
        int | None: Column index if found.
    """
    for alias in aliases:
        normalized_alias = alias.strip().lower()
        for i, header in enumerate(headers):
            if header == normalized_alias:
                return i
            # Partial match: header contains alias.
            if normalized_alias in header:
                return i
    return None
