"""Scan request model for orchestrated tool execution."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nocturna_engine.models.target import Target


class ScanRequest(BaseModel):
    """Represents an immutable request to run one scan workflow.

    Attributes:
        request_id: Unique request identifier.
        targets: Validated list of targets.
        tool_names: Optional explicit allow-list of plugin names.
        options: Arbitrary plugin options.
        timeout_seconds: Upper bound for tool execution timeout.
        retries: Retry attempts per async operation.
        concurrency_limit: Maximum concurrent tool execution count.
        metadata: Extra context for event correlation and reporting.
        created_at: UTC timestamp when request was created.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    targets: list[Target] = Field(min_length=1)
    tool_names: list[str] | None = Field(default=None)
    options: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=60.0, gt=0.0, le=3600.0)
    retries: int = Field(default=2, ge=0, le=10)
    concurrency_limit: int = Field(default=4, ge=1, le=128)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("tool_names")
    @classmethod
    def normalize_tool_names(cls, value: list[str] | None) -> list[str] | None:
        """Normalize optional tool names into lower-case unique entries.

        Args:
            value: Candidate list of tool names.

        Returns:
            list[str] | None: Normalized tool names or None.
        """

        if value is None:
            return None
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_item in value:
            candidate = raw_item.strip().lower()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            normalized.append(candidate)
        return normalized or None

    def to_json(self) -> str:
        """Serialize request to JSON string.

        Returns:
            str: JSON payload.
        """

        return self.model_dump_json()

    @classmethod
    def from_json(cls, payload: str) -> "ScanRequest":
        """Deserialize request from JSON.

        Args:
            payload: JSON string payload.

        Returns:
            ScanRequest: Parsed request model.
        """

        return cls.model_validate_json(payload)
