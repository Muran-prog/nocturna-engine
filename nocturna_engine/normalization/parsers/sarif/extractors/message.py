"""SARIF result message extraction."""

from __future__ import annotations

from typing import Any


def extract_message(result: dict[str, Any]) -> str:
    """Extract message text from a SARIF result."""
    message = result.get("message")
    if isinstance(message, dict):
        text = message.get("text", "")
        if text:
            return str(text).strip()
    return ""
