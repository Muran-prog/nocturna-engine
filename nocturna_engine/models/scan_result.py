"""Generic scan result model returned by every plugin."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from nocturna_engine.models.finding import Finding


class ScanResult(BaseModel):
    """Represents normalized output from one plugin execution.

    Attributes:
        result_id: Unique identifier of this tool run.
        request_id: Parent scan request identifier.
        tool_name: Plugin name that produced the result.
        success: Whether tool execution completed successfully.
        started_at: UTC start timestamp.
        finished_at: UTC finish timestamp.
        duration_ms: Execution duration in milliseconds.
        raw_output: Raw plugin payload before analysis.
        findings: Optional parsed findings from raw output.
        error_message: Error text if execution failed.
        metadata: Additional execution metadata.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    result_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    success: bool = Field(default=True)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = Field(default=0, ge=0)
    raw_output: dict[str, Any] | list[Any] | str | None = Field(default=None)
    findings: list[Finding] = Field(default_factory=list)
    error_message: str | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize result to JSON.

        Returns:
            str: JSON payload.
        """

        return self.model_dump_json()

    @classmethod
    def from_json(cls, payload: str) -> "ScanResult":
        """Deserialize result from JSON.

        Args:
            payload: JSON string payload.

        Returns:
            ScanResult: Parsed result.
        """

        return cls.model_validate_json(payload)

