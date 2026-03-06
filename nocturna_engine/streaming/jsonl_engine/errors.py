"""Typed exception hierarchy for the JSONL streaming engine."""

from __future__ import annotations

from typing import Any

from nocturna_engine.exceptions import NocturnaError
from nocturna_engine.streaming.jsonl_engine.models import EngineErrorKind


class JsonlEngineError(NocturnaError):
    """Base class for all JSONL engine runtime failures."""

    default_code = "jsonl_engine_error"
    default_category = "jsonl_engine"

    kind: EngineErrorKind = EngineErrorKind.UNKNOWN


class JsonlEngineCancelledError(JsonlEngineError):
    """Raised when the execution was cancelled by an external signal."""

    default_code = "jsonl_engine_cancelled"
    default_category = "jsonl_engine_lifecycle"

    kind = EngineErrorKind.CANCELLED


class JsonlEngineTimeoutError(JsonlEngineError):
    """Raised when execution exceeds the configured timeout."""

    default_code = "jsonl_engine_timeout"
    default_category = "jsonl_engine_lifecycle"
    default_retryable = True

    kind = EngineErrorKind.TIMEOUT


class JsonlSubprocessStartError(JsonlEngineError):
    """Raised when subprocess startup fails."""

    default_code = "jsonl_subprocess_start_error"
    default_category = "jsonl_engine_subprocess"

    kind = EngineErrorKind.SUBPROCESS


class JsonlOutputLimitExceededError(JsonlEngineError):
    """Raised when stdout/stderr exceed configured output limits."""

    default_code = "jsonl_output_limit_exceeded"
    default_category = "jsonl_engine_limits"

    kind = EngineErrorKind.OUTPUT_LIMIT


class JsonlMalformedLineError(JsonlEngineError):
    """Raised when one JSONL line cannot be decoded into an object."""

    default_code = "jsonl_malformed_line"
    default_category = "jsonl_engine_parsing"
    default_retryable = False

    kind = EngineErrorKind.MALFORMED_LINE

    def __init__(self, *, line_number: int, reason: str) -> None:
        """Initialize malformed-line error.

        Args:
            line_number: 1-based line index in stream.
            reason: Detailed parsing reason.
        """
        merged_context: dict[str, Any] = {
            "line_number": line_number,
            "reason": reason,
        }
        super().__init__(
            f"Malformed JSONL at line {line_number}: {reason}",
            context=merged_context,
        )
        self.line_number = line_number
        self.reason = reason


class JsonlLineTooLongError(JsonlEngineError):
    """Raised when one logical JSONL line exceeds `max_line_bytes`."""

    default_code = "jsonl_line_too_long"
    default_category = "jsonl_engine_limits"
    default_retryable = False

    kind = EngineErrorKind.OVERSIZED_LINE

    def __init__(self, *, line_number: int, max_line_bytes: int) -> None:
        """Initialize oversized-line error.

        Args:
            line_number: 1-based line index in stream.
            max_line_bytes: Configured max line size.
        """
        merged_context: dict[str, Any] = {
            "line_number": line_number,
            "max_line_bytes": max_line_bytes,
        }
        super().__init__(
            f"JSONL line {line_number} exceeded max line size ({max_line_bytes} bytes).",
            context=merged_context,
        )
        self.line_number = line_number
        self.max_line_bytes = max_line_bytes


class JsonlPolicyViolationError(JsonlEngineError):
    """Raised when configured malformed-threshold policy is violated."""

    default_code = "jsonl_policy_violation"
    default_category = "jsonl_engine_policy"

    kind = EngineErrorKind.POLICY


class JsonlHookExecutionError(JsonlEngineError):
    """Raised when hook callback execution fails in strict mode."""

    default_code = "jsonl_hook_execution_error"
    default_category = "jsonl_engine_hooks"

    kind = EngineErrorKind.HOOK_FAILURE


class JsonlExitCodeError(JsonlEngineError):
    """Raised when process exits with a disallowed code."""

    default_code = "jsonl_exit_code_error"
    default_category = "jsonl_engine_subprocess"

    kind = EngineErrorKind.NON_ZERO_EXIT

    def __init__(self, *, return_code: int, stderr: str) -> None:
        """Initialize non-zero-exit error.

        Args:
            return_code: Process exit code.
            stderr: Captured stderr output.
        """
        message = stderr or "no stderr output"
        merged_context: dict[str, Any] = {
            "return_code": return_code,
            "stderr": stderr,
        }
        super().__init__(
            f"Process exited with code {return_code}: {message}",
            context=merged_context,
        )
        self.return_code = return_code
        self.stderr = stderr


class JsonlTargetUnreachableError(JsonlExitCodeError):
    """Raised when stderr indicates unreachable host/network conditions."""

    default_code = "jsonl_target_unreachable"
    default_category = "jsonl_engine_network"
    default_retryable = True

    kind = EngineErrorKind.TARGET_UNREACHABLE
