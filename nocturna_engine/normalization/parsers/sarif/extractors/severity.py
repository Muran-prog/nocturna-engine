"""SARIF CWE, CVSS, and severity resolution."""

from __future__ import annotations

from typing import Any

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers._shared.patterns import (
    extract_cwe as _extract_cwe_from_text,
)
from nocturna_engine.normalization.parsers.base import ParserConfig
from nocturna_engine.normalization.parsers.sarif.constants import _SARIF_LEVEL_MAP


def extract_cwe(
    result: dict[str, Any],
    rule_meta: dict[str, Any],
) -> str | None:
    """Extract CWE identifier from rule metadata or result properties."""
    # Check rule properties.
    properties = rule_meta.get("properties")
    if isinstance(properties, dict):
        # Common patterns: properties.cwe, properties.tags containing CWE.
        cwe_value = properties.get("cwe")
        if cwe_value:
            return str(cwe_value).strip()

        tags = properties.get("tags")
        if isinstance(tags, list):
            for tag in tags:
                cwe_id = _extract_cwe_from_text(str(tag).strip())
                if cwe_id:
                    return cwe_id

    # Check result taxa references.
    taxa = result.get("taxa")
    if isinstance(taxa, list):
        for taxon in taxa:
            if isinstance(taxon, dict):
                taxon_id = str(taxon.get("id", ""))
                tool_component = taxon.get("toolComponent", {})
                if isinstance(tool_component, dict):
                    component_name = str(tool_component.get("name", "")).lower()
                    if "cwe" in component_name:
                        return f"CWE-{taxon_id}" if not taxon_id.upper().startswith("CWE") else taxon_id

    return None


def extract_cvss(rule_meta: dict[str, Any]) -> float | None:
    """Extract CVSS score from rule properties if available."""
    properties = rule_meta.get("properties")
    if isinstance(properties, dict):
        for key in ("cvss", "cvss_score", "cvssScore", "security-severity"):
            value = properties.get(key)
            if value is not None:
                try:
                    score = float(value)
                    if 0.0 <= score <= 10.0:
                        return score
                except (ValueError, TypeError):
                    continue
    return None


def resolve_severity(
    result: dict[str, Any],
    rule_meta: dict[str, Any],
    *,
    config: ParserConfig,
    tool_name: str,
) -> SeverityLevel:
    """Resolve final severity from SARIF level, rule config, and severity map.

    Resolution order (highest priority first):
    1. ``rule.properties["security-severity"]`` — CVSS-like score (0–10)
       used by GitHub/CodeQL.  Resolved via ``SeverityMap.resolve_cvss``.
    2. ``rule.defaultConfiguration.level`` — rule-defined SARIF level.
    3. ``result.level`` — per-result SARIF level (default ``"warning"``).

    Args:
        result: SARIF result object.
        rule_meta: Rule metadata for severity override.
        config: Parser configuration (for severity_map).
        tool_name: Tool name for severity map resolution.

    Returns:
        SeverityLevel: Resolved severity.
    """
    # Priority 1: security-severity CVSS-like score from rule properties.
    security_severity = _extract_security_severity(rule_meta)
    if security_severity is not None:
        return config.severity_map.resolve_cvss(security_severity)

    # Priority 2+3: SARIF level mapping.
    raw_level = str(result.get("level", "warning")).strip().lower()
    mapped_severity_str = _SARIF_LEVEL_MAP.get(raw_level, raw_level)

    # Check rule defaultConfiguration for severity override.
    default_config = rule_meta.get("defaultConfiguration")
    if isinstance(default_config, dict):
        rule_level = default_config.get("level")
        if rule_level:
            mapped_severity_str = _SARIF_LEVEL_MAP.get(
                str(rule_level).strip().lower(),
                mapped_severity_str,
            )

    return config.severity_map.resolve(
        mapped_severity_str,
        tool_name=tool_name,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_security_severity(rule_meta: dict[str, Any]) -> float | None:
    """Extract ``security-severity`` CVSS-like score from rule properties.

    GitHub/CodeQL emit this as a string-encoded float in the range 0–10.
    """
    properties = rule_meta.get("properties")
    if not isinstance(properties, dict):
        return None

    value = properties.get("security-severity")
    if value is None:
        return None

    try:
        score = float(value)
    except (ValueError, TypeError):
        return None

    if 0.0 <= score <= 10.0:
        return score
    return None
