"""Parser configuration container."""

from __future__ import annotations

from typing import Any

from nocturna_engine.normalization.severity import SeverityMap


class ParserConfig:
    """Configuration passed to parsers during initialization.

    Attributes:
        tool_name: Name of the tool whose output is being parsed.
        target_hint: Optional default target if not available in parsed data.
        severity_map: Severity mapping configuration.
        preserve_raw: Whether to preserve raw records in finding metadata.
        source_reference: Opaque reference to the input source for traceability.
        extra: Arbitrary parser-specific options.
    """

    __slots__ = (
        "tool_name",
        "target_hint",
        "severity_map",
        "preserve_raw",
        "source_reference",
        "max_input_bytes",
        "extra",
    )

    def __init__(
        self,
        *,
        tool_name: str,
        target_hint: str | None = None,
        severity_map: SeverityMap | None = None,
        preserve_raw: bool = True,
        source_reference: str | None = None,
        max_input_bytes: int = 256 * 1024 * 1024,  # 256 MB
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.target_hint = target_hint
        self.severity_map = severity_map or SeverityMap()
        self.preserve_raw = preserve_raw
        self.source_reference = source_reference
        self.max_input_bytes = max_input_bytes
        self.extra = dict(extra) if extra else {}
