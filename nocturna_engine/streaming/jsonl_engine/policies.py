"""Runtime policy objects for JSONL engine error and exit handling."""

from __future__ import annotations

from dataclasses import dataclass

from nocturna_engine.streaming.jsonl_engine.errors import (
    JsonlExitCodeError,
    JsonlPolicyViolationError,
    JsonlTargetUnreachableError,
)
from nocturna_engine.streaming.jsonl_engine.models import ErrorMode, JsonlPolicyConfig, JsonlStreamStats


@dataclass(slots=True)
class ErrorPolicy:
    """Decides whether runtime issues are fatal or skippable."""

    mode: ErrorMode = ErrorMode.TOLERANT

    @property
    def is_strict(self) -> bool:
        """Check if strict mode is enabled.

        Returns:
            bool: True when runtime should fail fast on issue.
        """

        return self.mode == ErrorMode.STRICT

    def should_raise(self, _error: Exception) -> bool:
        """Return whether given error should stop the stream.

        Args:
            _error: Raised exception.

        Returns:
            bool: True in strict mode, otherwise False.
        """

        return self.is_strict


@dataclass(slots=True)
class ExitCodePolicy:
    """Validates process exit codes and optionally detects unreachable targets."""

    fail_on_non_zero_exit: bool = True
    allowed_exit_codes: set[int] | None = None
    host_unreachable_hints: tuple[str, ...] = ()

    def validate(self, *, return_code: int, stderr: str) -> None:
        """Validate process return code against policy.

        Args:
            return_code: Process exit code.
            stderr: Captured stderr output.

        Raises:
            JsonlTargetUnreachableError: If stderr indicates unreachable target.
            JsonlExitCodeError: If return code is disallowed.
        """

        if not self.fail_on_non_zero_exit:
            return

        allowed_codes = self.allowed_exit_codes or {0}
        if return_code in allowed_codes:
            return

        lowered_stderr = stderr.lower()
        if self.host_unreachable_hints and any(
            hint.lower() in lowered_stderr for hint in self.host_unreachable_hints
        ):
            raise JsonlTargetUnreachableError(return_code=return_code, stderr=stderr)
        raise JsonlExitCodeError(return_code=return_code, stderr=stderr)


@dataclass(slots=True)
class MalformedThresholdPolicy:
    """Enforces emergency-stop thresholds for malformed JSON ratio/count."""

    max_malformed_count: int | None = None
    max_malformed_ratio: float | None = None

    def validate(self, stats: JsonlStreamStats) -> None:
        """Validate malformed counters against configured thresholds.

        Args:
            stats: Runtime stats snapshot.

        Raises:
            JsonlPolicyViolationError: If malformed thresholds are exceeded.
        """

        if self.max_malformed_count is not None and stats.malformed_lines > self.max_malformed_count:
            raise JsonlPolicyViolationError(
                "Malformed JSON line threshold exceeded: "
                f"{stats.malformed_lines} > {self.max_malformed_count}."
            )

        if self.max_malformed_ratio is None:
            return
        if stats.total_lines <= 0:
            return

        ratio = stats.malformed_lines / float(stats.total_lines)
        if ratio > self.max_malformed_ratio:
            raise JsonlPolicyViolationError(
                "Malformed JSON ratio threshold exceeded: "
                f"{ratio:.6f} > {self.max_malformed_ratio:.6f}."
            )


def build_policies(config: JsonlPolicyConfig) -> tuple[ErrorPolicy, ExitCodePolicy, MalformedThresholdPolicy]:
    """Build runtime policy objects from config model.

    Args:
        config: Policy configuration payload.

    Returns:
        tuple[ErrorPolicy, ExitCodePolicy, MalformedThresholdPolicy]: Runtime policies.
    """

    return (
        ErrorPolicy(mode=config.error_mode),
        ExitCodePolicy(
            fail_on_non_zero_exit=config.fail_on_non_zero_exit,
            allowed_exit_codes=set(config.allowed_exit_codes),
            host_unreachable_hints=tuple(config.host_unreachable_hints),
        ),
        MalformedThresholdPolicy(
            max_malformed_count=config.malformed_max_count,
            max_malformed_ratio=config.malformed_max_ratio,
        ),
    )

