"""Typed models for the reusable JSONL streaming engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ErrorMode(str, Enum):
    """Error-handling mode for runtime parsing and callback failures."""

    TOLERANT = "tolerant"
    STRICT = "strict"


class EngineErrorKind(str, Enum):
    """Normalized error categories used in :class:`JsonlEngineResult`."""

    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    SUBPROCESS = "subprocess"
    OUTPUT_LIMIT = "output_limit"
    MALFORMED_LINE = "malformed_line"
    OVERSIZED_LINE = "oversized_line"
    NON_ZERO_EXIT = "non_zero_exit"
    TARGET_UNREACHABLE = "target_unreachable"
    POLICY = "policy"
    HOOK_FAILURE = "hook_failure"
    UNKNOWN = "unknown"


class JsonlParserConfig(BaseModel):
    """Parser controls for chunk/line assembly and JSON decoding."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    max_line_bytes: int = Field(default=1024 * 1024, ge=256)
    chunk_size: int = Field(default=8192, ge=64)
    max_issue_line_chars: int = Field(default=1024, ge=64, le=8192)


class JsonlOutputLimits(BaseModel):
    """Hard limits for combined process output and stderr collection."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    max_output_bytes: int = Field(default=200 * 1024 * 1024, ge=1024)
    max_stderr_bytes: int | None = Field(default=16 * 1024 * 1024, ge=1024)


class JsonlHeartbeatConfig(BaseModel):
    """Heartbeat/progress callback cadence configuration."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    every_records: int | None = Field(default=100, ge=1)
    every_seconds: float | None = Field(default=5.0, gt=0.0)


class JsonlPolicyConfig(BaseModel):
    """Policy configuration for errors, exit code checks, and malformed thresholds."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    error_mode: ErrorMode = ErrorMode.TOLERANT
    fail_on_non_zero_exit: bool = True
    allowed_exit_codes: set[int] = Field(default_factory=lambda: {0})
    malformed_max_count: int | None = Field(default=None, ge=1)
    malformed_max_ratio: float | None = Field(default=None, gt=0.0, le=1.0)
    host_unreachable_hints: tuple[str, ...] = Field(default_factory=tuple)


class JsonlEngineConfig(BaseModel):
    """Runtime configuration for one JSONL streaming process execution."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    command: list[str] = Field(min_length=1)
    timeout_seconds: float = Field(default=300.0, gt=0.0)
    queue_maxsize: int = Field(default=512, ge=1, le=10_000)
    collect_records: bool = True
    parser: JsonlParserConfig = Field(default_factory=JsonlParserConfig)
    limits: JsonlOutputLimits = Field(default_factory=JsonlOutputLimits)
    heartbeat: JsonlHeartbeatConfig = Field(default_factory=JsonlHeartbeatConfig)
    policies: JsonlPolicyConfig = Field(default_factory=JsonlPolicyConfig)

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: list[str]) -> list[str]:
        """Validate subprocess command arguments for unsafe values.

        Args:
            value: Candidate command argument list.

        Returns:
            list[str]: Trimmed command list.

        Raises:
            ValueError: If command is empty or contains unsafe arguments.
        """

        normalized: list[str] = []
        for argument in value:
            text = str(argument)
            if not text.strip():
                raise ValueError("Command arguments must be non-empty strings.")
            if "\x00" in text:
                raise ValueError("Command arguments must not contain null bytes.")
            normalized.append(text.strip())
        if not normalized:
            raise ValueError("Command cannot be empty.")
        return normalized


@dataclass(slots=True, frozen=True)
class JsonlRecordEnvelope:
    """Represents one parsed JSONL record with its source line metadata."""

    line_number: int
    raw_line: str
    payload: dict[str, Any]


@dataclass(slots=True, frozen=True)
class JsonlIssueEnvelope:
    """Represents one non-fatal parsing or hook issue observed in the stream."""

    line_number: int | None
    raw_line: str | None
    error: Exception
    source: str


@dataclass(slots=True)
class JsonlStreamStats:
    """Execution counters and derived metrics for one JSONL stream run."""

    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    oversized_lines: int = 0
    skipped_lines: int = 0
    emitted_records: int = 0
    bytes_read: int = 0
    duration_seconds: float = 0.0
    throughput_records_per_second: float = 0.0

    def copy(self) -> JsonlStreamStats:
        """Create a mutable copy of counters.

        Returns:
            JsonlStreamStats: Snapshot copy.
        """

        return JsonlStreamStats(
            total_lines=self.total_lines,
            parsed_lines=self.parsed_lines,
            malformed_lines=self.malformed_lines,
            oversized_lines=self.oversized_lines,
            skipped_lines=self.skipped_lines,
            emitted_records=self.emitted_records,
            bytes_read=self.bytes_read,
            duration_seconds=self.duration_seconds,
            throughput_records_per_second=self.throughput_records_per_second,
        )

    def to_dict(self) -> dict[str, int | float]:
        """Serialize counters to a JSON-friendly dictionary.

        Returns:
            dict[str, int | float]: Counter and metric values.
        """

        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "malformed_lines": self.malformed_lines,
            "oversized_lines": self.oversized_lines,
            "skipped_lines": self.skipped_lines,
            "emitted_records": self.emitted_records,
            "bytes_read": self.bytes_read,
            "duration_seconds": round(max(self.duration_seconds, 0.0), 6),
            "throughput_records_per_second": round(max(self.throughput_records_per_second, 0.0), 6),
        }


@dataclass(slots=True)
class JsonlEngineResult:
    """Normalized streaming-engine result used by callers and adapters."""

    records: list[dict[str, Any]]
    stats: JsonlStreamStats
    stderr: str
    return_code: int
    command: str
    duration_seconds: float
    error: str | None = None
    error_kind: EngineErrorKind | None = None
    was_cancelled: bool = False
