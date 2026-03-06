"""Constants for the SARIF v2.1.0 parser."""

from __future__ import annotations

# SARIF level → default severity mapping (overridable via SeverityMap).
_SARIF_LEVEL_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}
