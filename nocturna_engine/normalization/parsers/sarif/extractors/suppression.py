"""SARIF suppression detection."""

from __future__ import annotations

from typing import Any


def is_suppressed(result: dict[str, Any]) -> tuple[bool, str]:
    """Check whether a SARIF result is suppressed.

    A result is considered suppressed when its ``suppressions`` array
    contains at least one entry with ``status == "accepted"``.

    Returns:
        Tuple of (is_suppressed, reason).  *reason* is the suppression
        ``kind`` or a generic message when the result should be skipped.
    """
    suppressions = result.get("suppressions")
    if not isinstance(suppressions, list):
        return False, ""

    for suppression in suppressions:
        if not isinstance(suppression, dict):
            continue
        status = str(suppression.get("status", "")).strip().lower()
        if status == "accepted":
            kind = str(suppression.get("kind", "suppressed")).strip()
            justification = str(suppression.get("justification", "")).strip()
            reason = kind
            if justification:
                reason = f"{kind}: {justification}"
            return True, reason

    return False, ""
