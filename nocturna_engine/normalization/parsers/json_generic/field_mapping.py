"""Tool-specific field mapping heuristics for generic JSON parsing.

Field extraction strategies for known tool output shapes.
Each strategy is a dict describing where to find key finding fields.
"""

from __future__ import annotations

from typing import Any


# Field extraction strategies for known tool output shapes.
# Each strategy is a dict describing where to find key finding fields.
_TOOL_FIELD_MAPS: dict[str, dict[str, str | list[str]]] = {
    "nuclei": {
        "title_fields": ["info.name", "template-id", "templateID"],
        "description_fields": ["info.description", "info.name"],
        "severity_fields": ["info.severity", "severity"],
        "target_fields": ["host", "matched-at", "ip"],
        "cwe_fields": ["info.classification.cwe-id", "info.classification.cwe"],
        "cvss_fields": ["info.classification.cvss-score"],
        "evidence_include": [
            "template-id", "matcher-name", "matched-at",
            "type", "extracted-results", "curl-command",
        ],
        "discriminator_fields": ["template-id", "info"],
    },
    "semgrep_json": {
        "title_fields": ["check_id", "extra.metadata.rule-id"],
        "description_fields": ["extra.message", "extra.metadata.message"],
        "severity_fields": ["extra.severity", "severity"],
        "target_fields": ["path", "extra.metadata.target"],
        "cwe_fields": ["extra.metadata.cwe"],
        "cvss_fields": [],
        "evidence_include": [
            "check_id", "start", "end", "extra.lines",
        ],
        "discriminator_fields": ["check_id", "extra"],
    },
}


def _deep_get(obj: dict[str, Any], path: str) -> Any:
    """Navigate a dotted path in a nested dict.

    Args:
        obj: Source dictionary.
        path: Dot-separated key path.

    Returns:
        Any: Value at path, or None if not found.
    """
    current: Any = obj
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _first_non_empty(obj: dict[str, Any], paths: list[str]) -> str:
    """Return the first non-empty string value from a list of dotted paths."""
    for path in paths:
        value = _deep_get(obj, path)
        if value is not None:
            text = str(value).strip()
            if text:
                return text
    return ""


def _detect_tool_shape(record: dict[str, Any]) -> str | None:
    """Detect which tool likely produced a JSON record.

    Args:
        record: Parsed JSON object.

    Returns:
        str | None: Tool name key into _TOOL_FIELD_MAPS, or None.
    """
    for tool_key, field_map in _TOOL_FIELD_MAPS.items():
        discriminators = field_map.get("discriminator_fields", [])
        if isinstance(discriminators, list):
            matches = sum(
                1
                for field in discriminators
                if _deep_get(record, field) is not None
            )
            if matches == len(discriminators) and matches > 0:
                return tool_key
    return None
