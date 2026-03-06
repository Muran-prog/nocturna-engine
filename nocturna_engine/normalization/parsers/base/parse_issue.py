"""Non-fatal parsing issue representation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class ParseIssue:
    """Represents a non-fatal parsing issue encountered during normalization.

    Attributes:
        message: Human-readable description of the issue.
        line_number: Optional 1-based line number in source.
        raw_record: Optional raw record that caused the issue.
        error: Optional underlying exception.
    """

    message: str
    line_number: int | None = None
    raw_record: dict[str, Any] | None = None
    error: Exception | None = None
