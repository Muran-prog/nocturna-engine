"""Validation helpers used by orchestration components."""

from __future__ import annotations

import re

from nocturna_engine.exceptions import ValidationError

PLUGIN_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


def validate_non_empty(value: str, field_name: str) -> str:
    """Ensure a string field is not empty.

    Args:
        value: Input value.
        field_name: Human-readable field name.

    Returns:
        str: Normalized string.

    Raises:
        ValidationError: If value is empty.
    """

    normalized = value.strip()
    if not normalized:
        raise ValidationError(f"Field '{field_name}' must be non-empty.")
    return normalized


def validate_plugin_name(name: str) -> str:
    """Validate plugin registry name.

    Args:
        name: Plugin name candidate.

    Returns:
        str: Lowercased validated plugin name.

    Raises:
        ValidationError: If name format is invalid.
    """

    candidate = validate_non_empty(name, "plugin name").lower()
    if PLUGIN_NAME_PATTERN.match(candidate) is None:
        raise ValidationError(
            "Plugin name must match pattern ^[a-z][a-z0-9_-]{1,63}$."
        )
    return candidate

