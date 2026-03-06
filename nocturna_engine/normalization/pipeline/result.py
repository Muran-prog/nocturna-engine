"""Normalization pipeline result model."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.detector import DetectionResult
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import ParseIssue


class NormalizationResult(BaseModel):
    """Result of a normalization pipeline run.

    Attributes:
        findings: Normalized, deduplicated Finding objects.
        issues: Non-fatal parsing issues encountered.
        stats: Aggregate normalization statistics.
        detection: Format detection metadata.
        parser_name: Name of the parser that was used.
        aborted: Whether the run was aborted due to error threshold.
        abort_reason: Human-readable reason for abort.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    findings: list[Finding] = Field(default_factory=list)
    issues: list[ParseIssue] = Field(default_factory=list)
    stats: NormalizationStats = Field(default_factory=NormalizationStats)
    detection: DetectionResult | None = Field(default=None)
    parser_name: str = Field(default="")
    aborted: bool = Field(default=False)
    abort_reason: str | None = Field(default=None)
