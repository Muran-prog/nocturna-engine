"""Utility helpers for the generic XML parser."""

from __future__ import annotations

import re
from typing import Any

from nocturna_engine.normalization.parsers._shared.patterns import (
    extract_cves,
    extract_cwe,
    extract_first_cve,
)
from nocturna_engine.normalization.parsers.base import ParserConfig

# Re-export shared CVE/CWE helpers so existing imports keep working.
__all__ = ["extract_cves", "extract_cwe", "extract_first_cve"]

# Pre-compiled pattern for CVSS extraction (local to xml_generic).
_CVSS_SCORE_PATTERN = re.compile(r"\d+\.\d+")


def parse_cvss_score(value: str) -> float | None:
    """Parse a CVSS score string to float, validating range 0.0-10.0.

    Args:
        value: String representation of a CVSS score.

    Returns:
        Float score if valid, or None.
    """
    stripped = value.strip()
    if not stripped:
        return None
    match = _CVSS_SCORE_PATTERN.search(stripped)
    if not match:
        return None
    try:
        score = float(match.group(0))
    except (ValueError, OverflowError):
        return None
    if 0.0 <= score <= 10.0:
        return score
    return None


def safe_int(value: str, default: int = 0) -> int:
    """Parse integer from string with fallback.

    Args:
        value: String to parse.
        default: Fallback value on parse failure.

    Returns:
        Parsed int or default.
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def truncate(text: str, max_length: int = 2048) -> str:
    """Truncate text to max_length, appending ellipsis if truncated.

    Args:
        text: Text to truncate.
        max_length: Maximum allowed length.

    Returns:
        Truncated text.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def build_parser_origin(
    *,
    config: ParserConfig,
    original_record: dict[str, Any] | None,
    original_severity: str | None = None,
) -> Any:
    """Build a NormalizationOrigin for xml_generic parser.

    Args:
        config: Parser configuration.
        original_record: Raw record if preservation is enabled.
        original_severity: Tool-native severity string before mapping.

    Returns:
        NormalizationOrigin instance.
    """
    from nocturna_engine.normalization.metadata import NormalizationOrigin

    return NormalizationOrigin(
        parser_name="xml_generic",
        tool_name=config.tool_name,
        source_format="xml",
        source_reference=config.source_reference,
        original_severity=original_severity,
        original_record=original_record if config.preserve_raw else None,
    )
