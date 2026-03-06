"""Raw data preservation and normalization context tracking."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NormalizationOrigin(BaseModel):
    """Tracks the source of a normalized finding for forensic traceability.

    Attributes:
        parser_name: Name of the parser that produced this finding.
        tool_name: Security tool that generated the raw output.
        source_format: Detected format of the input data.
        source_reference: Opaque reference to raw data (file path, stream id, etc.).
        original_severity: Tool-native severity string before normalization.
        original_record: Preserved raw record from tool output for forensic review.
        line_number: Line number in source where this finding originated.
        normalized_at: UTC timestamp of normalization.
    """

    model_config = ConfigDict(extra="forbid")

    parser_name: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    source_format: str = Field(min_length=1)
    source_reference: str | None = Field(default=None)
    original_severity: str | None = Field(default=None)
    original_record: dict[str, Any] | None = Field(default=None)
    line_number: int | None = Field(default=None, ge=1)
    normalized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def attach_normalization_origin(
    metadata: dict[str, Any],
    origin: NormalizationOrigin,
) -> dict[str, Any]:
    """Attach normalization origin to a finding's metadata dict.

    Does not mutate the input dict — returns a new dict with
    ``_normalization`` key added.

    Args:
        metadata: Existing finding metadata.
        origin: Normalization origin to attach.

    Returns:
        dict[str, Any]: New metadata dict with origin attached.
    """
    return {**metadata, "_normalization": origin.model_dump(mode="json")}


class NormalizationStats(BaseModel):
    """Aggregate counters for one normalization pipeline run.

    Attributes:
        total_records_processed: Total raw records seen by parser.
        findings_produced: Number of valid Finding objects produced.
        records_skipped: Records that did not produce findings (e.g. non-vuln data).
        errors_encountered: Number of parse errors encountered.
        duplicates_merged: Number of findings merged via fingerprint dedup.
        duration_seconds: Wall-clock duration of the normalization run.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    total_records_processed: int = Field(default=0, ge=0)
    findings_produced: int = Field(default=0, ge=0)
    records_skipped: int = Field(default=0, ge=0)
    errors_encountered: int = Field(default=0, ge=0)
    duplicates_merged: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0.0)

    @property
    def error_rate(self) -> float:
        """Calculate the ratio of errors to total records processed."""
        if self.total_records_processed <= 0:
            return 0.0
        return self.errors_encountered / self.total_records_processed

    @property
    def success_rate(self) -> float:
        """Calculate the ratio of findings produced to total records processed."""
        if self.total_records_processed <= 0:
            return 0.0
        return self.findings_produced / self.total_records_processed
