"""Public entry point for format detection."""

from __future__ import annotations

from typing import Any

import structlog

from nocturna_engine.normalization.detector._hints import _resolve_hint
from nocturna_engine.normalization.detector._sniffers import _sniff_structure, _strip_bom
from nocturna_engine.normalization.detector._types import (
    DetectionResult,
    InputFormat,
    _SNIFF_SIZE,
)
from nocturna_engine.normalization.errors import FormatDetectionError

logger = structlog.get_logger("normalization.detector")


def detect_format(
    data: bytes | str,
    *,
    format_hint: str | None = None,
    tool_hint: str | None = None,
) -> DetectionResult:
    """Detect the format of raw security tool output.

    Uses a layered approach: explicit hint → structural sniffing → fallback.

    Args:
        data: Raw input data (first chunk is sufficient for detection).
        format_hint: Explicit format hint from caller (highest priority).
        tool_hint: Optional tool name hint for disambiguation.

    Returns:
        DetectionResult: Detected format with confidence metadata.

    Raises:
        FormatDetectionError: If format cannot be determined.
    """
    # Layer 1: Explicit hint — highest priority.
    if format_hint is not None:
        resolved = _resolve_hint(format_hint)
        if resolved is not None:
            return DetectionResult(
                format=resolved,
                confidence=1.0,
                method="explicit_hint",
                tool_hint=tool_hint,
            )
        logger.warning(
            "format_hint_unrecognized",
            hint=format_hint,
        )

    # Normalize input to bytes for sniffing.
    raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
    sample = _strip_bom(raw_bytes[:_SNIFF_SIZE])

    if not sample.strip():
        raise FormatDetectionError("Input data is empty.")

    # Layer 2: Structural sniffing.
    result = _sniff_structure(sample, tool_hint=tool_hint)
    if result is not None:
        return result

    # Layer 3: Fallback to plaintext.
    return DetectionResult(
        format=InputFormat.PLAINTEXT,
        confidence=0.3,
        method="fallback",
        tool_hint=tool_hint,
    )
