"""Utility helpers used across JSONL streaming engine modules."""

from __future__ import annotations

import inspect
import re
import shlex
from collections.abc import Awaitable, Sequence
from typing import TypeVar, cast

from nocturna_engine.streaming.jsonl_engine.errors import JsonlOutputLimitExceededError

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_SENSITIVE_FLAGS = {"--token", "--api-key", "--apikey", "--auth", "--header"}
_T = TypeVar("_T")


def truncate_text(value: str, *, max_chars: int) -> str:
    """Truncate text for safe logging or issue snapshots.

    Args:
        value: Input text.
        max_chars: Maximum output length.

    Returns:
        str: Truncated text.
    """

    if max_chars <= 0:
        return ""
    if len(value) <= max_chars:
        return value
    if max_chars <= 3:
        return value[:max_chars]
    return f"{value[: max_chars - 3]}..."


def sanitize_output(raw: str) -> str:
    """Normalize command output for stable parsing and reporting.

    Args:
        raw: Raw process output.

    Returns:
        str: Sanitized output text.
    """

    normalized = raw.encode("utf-8", errors="replace").decode("utf-8")
    normalized = _ANSI_ESCAPE_RE.sub("", normalized)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.strip()


def normalize_command(command: Sequence[object]) -> list[str]:
    """Validate and normalize subprocess command arguments.

    Args:
        command: Arbitrary command sequence.

    Returns:
        list[str]: Normalized command argument list.

    Raises:
        ValueError: If command is empty or includes unsafe arguments.
    """

    normalized: list[str] = []
    for argument in command:
        text = str(argument)
        if not text:
            raise ValueError("Subprocess command contains an empty argument.")
        if "\x00" in text:
            raise ValueError("Subprocess command contains null-byte arguments.")
        normalized.append(text)
    if not normalized:
        raise ValueError("Subprocess command cannot be empty.")
    return normalized


def format_command_for_log(command: Sequence[str]) -> str:
    """Return shell-quoted command string with sensitive values redacted.

    Args:
        command: Process command arguments.

    Returns:
        str: Redacted command string for logs.
    """

    masked: list[str] = []
    redact_next = False
    for argument in command:
        lowered = argument.lower()
        if redact_next:
            masked.append("***")
            redact_next = False
            continue
        if lowered in _SENSITIVE_FLAGS or argument == "-H":
            masked.append(argument)
            redact_next = True
            continue
        if "=" in argument and any(flag in lowered for flag in ("token=", "api_key=", "apikey=")):
            key = argument.split("=", 1)[0]
            masked.append(f"{key}=***")
            continue
        masked.append(argument)
    return " ".join(shlex.quote(part) for part in masked)


async def maybe_await(result: Awaitable[_T] | _T) -> _T:
    """Await values that may be sync or async callback results.

    Args:
        result: Callback result or awaitable.

    Returns:
        _T: Callback outcome.
    """

    if inspect.isawaitable(result):
        return await cast(Awaitable[_T], result)
    return cast(_T, result)


class OutputBudget:
    """Tracks output byte budgets across concurrent stdout/stderr readers."""

    def __init__(self, *, max_output_bytes: int, max_stderr_bytes: int | None) -> None:
        """Initialize byte-budget tracker.

        Args:
            max_output_bytes: Max combined bytes across stdout and stderr.
            max_stderr_bytes: Optional dedicated stderr limit.
        """

        self._max_output_bytes = max_output_bytes
        self._max_stderr_bytes = max_stderr_bytes
        self._total_bytes = 0
        self._stderr_bytes = 0

    def consume_stdout(self, count: int) -> None:
        """Consume stdout bytes and enforce global output limit.

        Args:
            count: Number of bytes consumed.

        Raises:
            JsonlOutputLimitExceededError: If limit is exceeded.
        """

        self._consume_total(count)

    def consume_stderr(self, count: int) -> None:
        """Consume stderr bytes and enforce global/per-stream limits.

        Args:
            count: Number of bytes consumed.

        Raises:
            JsonlOutputLimitExceededError: If limits are exceeded.
        """

        self._stderr_bytes += count
        if self._max_stderr_bytes is not None and self._stderr_bytes > self._max_stderr_bytes:
            raise JsonlOutputLimitExceededError(
                f"Stderr exceeded limit of {self._max_stderr_bytes} bytes."
            )
        self._consume_total(count)

    def _consume_total(self, count: int) -> None:
        self._total_bytes += count
        if self._total_bytes > self._max_output_bytes:
            raise JsonlOutputLimitExceededError(
                f"Process output exceeded limit of {self._max_output_bytes} bytes."
            )

    @property
    def total_bytes(self) -> int:
        """Return consumed combined output bytes."""

        return self._total_bytes

    @property
    def stderr_bytes(self) -> int:
        """Return consumed stderr bytes."""

        return self._stderr_bytes
