"""Normalization pipeline configuration model."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nocturna_engine.normalization.severity import SeverityMap, build_severity_map


class NormalizationConfig(BaseModel):
    """Configuration for a normalization pipeline run.

    Attributes:
        tool_name: Name of the security tool whose output is being normalized.
        target_hint: Default target when not available in parsed data.
        format_hint: Explicit format hint to skip detection.
        tool_hint: Tool name hint for parser disambiguation.
        severity_map: Severity mapping configuration.
        preserve_raw: Whether to preserve raw records in finding metadata.
        source_reference: Opaque reference to input source for traceability.
        deduplicate: Whether to merge findings with identical fingerprints.
        max_errors: Maximum parse errors before aborting (None = unlimited).
        max_error_rate: Maximum error rate before aborting (None = unlimited).
        parser_options: Extra parser-specific options.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    tool_name: str = Field(min_length=1)
    target_hint: str | None = Field(default=None)
    format_hint: str | None = Field(default=None)
    tool_hint: str | None = Field(default=None)
    severity_map: SeverityMap = Field(default_factory=build_severity_map)
    preserve_raw: bool = Field(default=True)
    source_reference: str | None = Field(default=None)
    deduplicate: bool = Field(default=True)
    max_errors: int | None = Field(default=None, ge=1)
    max_error_rate: float | None = Field(default=None, gt=0.0, le=1.0)
    parser_options: dict[str, Any] = Field(default_factory=dict)
