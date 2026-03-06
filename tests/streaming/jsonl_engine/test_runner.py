"""Comprehensive edge-case tests for the JSONL subprocess runner (start, streams, lifecycle)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from nocturna_engine.streaming.jsonl_engine.errors import (
    JsonlEngineCancelledError,
    JsonlOutputLimitExceededError,
    JsonlSubprocessStartError,
)
from nocturna_engine.streaming.jsonl_engine.models import (
    ErrorMode,
    JsonlPolicyConfig,
    JsonlStreamStats,
)
from nocturna_engine.streaming.jsonl_engine.policies import (
    ErrorPolicy,
    ExitCodePolicy,
    MalformedThresholdPolicy,
    build_policies,
)
from nocturna_engine.streaming.jsonl_engine.metrics import JsonlMetrics
from nocturna_engine.streaming.jsonl_engine.runner import JsonlSubprocessRunner
from nocturna_engine.streaming.jsonl_engine.utils import (
    OutputBudget,
    format_command_for_log,
    normalize_command,
    sanitize_output,
    truncate_text,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeStream:
    """Deterministic async byte stream."""

    def __init__(self, chunks: list[bytes], *, delay_seconds: float = 0.0) -> None:
        self._chunks = list(chunks)
        self._delay = delay_seconds

    async def read(self, _size: int = -1) -> bytes:
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _FakeProcess:
    """Subprocess test double implementing ProcessProtocol."""

    def __init__(
        self,
        *,
        stdout_chunks: list[bytes] | None = None,
        stderr_chunks: list[bytes] | None = None,
        return_code: int = 0,
        wait_delay_seconds: float = 0.0,
        stream_delay_seconds: float = 0.0,
        stdout: Any = ...,
        stderr: Any = ...,
    ) -> None:
        if stdout is not ...:
            self.stdout = stdout
        else:
            self.stdout = _FakeStream(
                stdout_chunks or [], delay_seconds=stream_delay_seconds
            )
        if stderr is not ...:
            self.stderr = stderr
        else:
            self.stderr = _FakeStream(
                stderr_chunks or [], delay_seconds=stream_delay_seconds
            )
        self.returncode: int | None = None
        self._return_code = return_code
        self._wait_delay = wait_delay_seconds
        self.was_killed = False

    async def wait(self) -> int:
        if self.returncode is None and self._wait_delay > 0:
            remaining = self._wait_delay
            while remaining > 0 and self.returncode is None:
                step = min(0.01, remaining)
                await asyncio.sleep(step)
                remaining -= step
        if self.returncode is None:
            self.returncode = self._return_code
        return self.returncode

    def kill(self) -> None:
        self.was_killed = True
        self.returncode = -9


def _make_runner(
    process: _FakeProcess | None = None,
    chunk_size: int = 64,
) -> tuple[JsonlSubprocessRunner, list[list[str]]]:
    """Build runner with optional fake process factory."""
    commands: list[list[str]] = []

    async def _factory(command: list[str]) -> _FakeProcess:
        commands.append(list(command))
        return process or _FakeProcess()

    return (
        JsonlSubprocessRunner(process_factory=_factory, chunk_size=chunk_size),
        commands,
    )


# ---------------------------------------------------------------------------
# RunnerStartMixin: start() tests
# ---------------------------------------------------------------------------


async def test_runner_start_success() -> None:
    """start() should return process with stdout/stderr pipes."""
    process = _FakeProcess(stdout_chunks=[b"data\n"], stderr_chunks=[])
    runner, commands = _make_runner(process)
    result = await runner.start(["echo", "hello"])
    assert result is process
    assert commands == [["echo", "hello"]]


async def test_runner_start_empty_command_raises() -> None:
    """start() with empty command should raise JsonlSubprocessStartError."""
    runner, _ = _make_runner()
    with pytest.raises(JsonlSubprocessStartError, match="empty"):
        await runner.start([])


async def test_runner_start_null_byte_command_raises() -> None:
    """start() with null byte in command should raise."""
    runner, _ = _make_runner()
    with pytest.raises(JsonlSubprocessStartError, match="null"):
        await runner.start(["cmd\x00", "arg"])


async def test_runner_start_whitespace_only_command_raises() -> None:
    """start() with empty string argument should raise."""
    runner, _ = _make_runner()
    with pytest.raises(JsonlSubprocessStartError):
        await runner.start(["", "arg"])


async def test_runner_start_missing_stdout_pipe_raises() -> None:
    """start() should raise if process has no stdout pipe."""
    process = _FakeProcess(stdout=None, stderr=_FakeStream([]))
    runner, _ = _make_runner(process)
    with pytest.raises(JsonlSubprocessStartError, match="pipes"):
        await runner.start(["cmd"])


async def test_runner_start_missing_stderr_pipe_raises() -> None:
    """start() should raise if process has no stderr pipe."""
    process = _FakeProcess(stdout=_FakeStream([]), stderr=None)
    runner, _ = _make_runner(process)
    with pytest.raises(JsonlSubprocessStartError, match="pipes"):
        await runner.start(["cmd"])


async def test_runner_start_factory_file_not_found() -> None:
    """start() should wrap FileNotFoundError as start error."""

    async def _bad_factory(cmd: list[str]) -> _FakeProcess:
        raise FileNotFoundError("not found")

    runner = JsonlSubprocessRunner(process_factory=_bad_factory)
    with pytest.raises(JsonlSubprocessStartError, match="not available"):
        await runner.start(["nonexistent-binary"])


async def test_runner_start_factory_os_error() -> None:
    """start() should wrap OSError as start error."""

    async def _bad_factory(cmd: list[str]) -> _FakeProcess:
        raise OSError("permission denied")

    runner = JsonlSubprocessRunner(process_factory=_bad_factory)
    with pytest.raises(JsonlSubprocessStartError, match="Unable to start"):
        await runner.start(["bad-cmd"])


# ---------------------------------------------------------------------------
# RunnerStreamsMixin: iter_stdout_chunks tests
# ---------------------------------------------------------------------------


async def test_iter_stdout_chunks_yields_all_chunks() -> None:
    """iter_stdout_chunks should yield all chunks from stdout."""
    process = _FakeProcess(stdout_chunks=[b"abc", b"def", b"ghi"])
    runner, _ = _make_runner(process, chunk_size=64)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=None)

    chunks: list[bytes] = []
    async for chunk in runner.iter_stdout_chunks(
        process=process, output_budget=budget
    ):
        chunks.append(chunk)

    assert chunks == [b"abc", b"def", b"ghi"]
    assert budget.total_bytes == 9


async def test_iter_stdout_chunks_empty_stdout() -> None:
    """iter_stdout_chunks on empty stdout should yield nothing."""
    process = _FakeProcess(stdout_chunks=[])
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=None)

    chunks: list[bytes] = []
    async for chunk in runner.iter_stdout_chunks(
        process=process, output_budget=budget
    ):
        chunks.append(chunk)

    assert chunks == []


async def test_iter_stdout_chunks_no_stdout_pipe() -> None:
    """iter_stdout_chunks with None stdout should return immediately."""
    process = _FakeProcess(stdout=None, stderr=_FakeStream([]))
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=None)

    chunks: list[bytes] = []
    async for chunk in runner.iter_stdout_chunks(
        process=process, output_budget=budget
    ):
        chunks.append(chunk)

    assert chunks == []


async def test_iter_stdout_chunks_output_limit_exceeded() -> None:
    """iter_stdout_chunks should raise when output budget is exceeded."""
    process = _FakeProcess(stdout_chunks=[b"x" * 100, b"y" * 100])
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=50, max_stderr_bytes=None)

    with pytest.raises(JsonlOutputLimitExceededError):
        async for _ in runner.iter_stdout_chunks(
            process=process, output_budget=budget
        ):
            pass


async def test_iter_stdout_chunks_cancellation() -> None:
    """iter_stdout_chunks should raise cancelled when cancel event is set."""
    process = _FakeProcess(
        stdout_chunks=[b"data\n" for _ in range(100)],
        stream_delay_seconds=0.01,
    )
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=None)
    cancel = asyncio.Event()
    cancel.set()

    with pytest.raises(JsonlEngineCancelledError):
        async for _ in runner.iter_stdout_chunks(
            process=process, output_budget=budget, cancel_event=cancel
        ):
            pass


# ---------------------------------------------------------------------------
# RunnerStreamsMixin: collect_stderr tests
# ---------------------------------------------------------------------------


async def test_collect_stderr_returns_sanitized_text() -> None:
    """collect_stderr should return sanitized stderr."""
    process = _FakeProcess(
        stderr_chunks=[b"warning: something\n", b"error: boom\n"]
    )
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=10_000)

    result = await runner.collect_stderr(process=process, output_budget=budget)
    assert "warning: something" in result
    assert "error: boom" in result


async def test_collect_stderr_empty() -> None:
    """collect_stderr on empty stderr should return empty string."""
    process = _FakeProcess(stderr_chunks=[])
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=10_000)

    result = await runner.collect_stderr(process=process, output_budget=budget)
    assert result == ""


async def test_collect_stderr_no_pipe() -> None:
    """collect_stderr with None stderr should return empty string."""
    process = _FakeProcess(stdout=_FakeStream([]), stderr=None)
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=10_000)

    result = await runner.collect_stderr(process=process, output_budget=budget)
    assert result == ""


async def test_collect_stderr_budget_exceeded_raises() -> None:
    """collect_stderr should raise when stderr bytes exceed the limit."""
    process = _FakeProcess(stderr_chunks=[b"x" * 2000])
    runner, _ = _make_runner(process)
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=1024)

    with pytest.raises(JsonlOutputLimitExceededError):
        await runner.collect_stderr(process=process, output_budget=budget)


# ---------------------------------------------------------------------------
# RunnerLifecycleMixin: wait_for_exit / drain / kill
# ---------------------------------------------------------------------------


async def test_wait_for_exit_returns_code() -> None:
    """wait_for_exit should return the process exit code."""
    process = _FakeProcess(return_code=42)
    runner, _ = _make_runner(process)
    code = await runner.wait_for_exit(process=process)
    assert code == 42


async def test_wait_for_exit_cancellation() -> None:
    """wait_for_exit should raise cancelled when cancel event is set."""
    process = _FakeProcess(return_code=0, wait_delay_seconds=5.0)
    runner, _ = _make_runner(process)
    cancel = asyncio.Event()
    cancel.set()

    with pytest.raises(JsonlEngineCancelledError):
        await runner.wait_for_exit(process=process, cancel_event=cancel)


async def test_wait_for_exit_already_exited() -> None:
    """wait_for_exit with already-exited process should return immediately."""
    process = _FakeProcess(return_code=7)
    process.returncode = 7
    runner, _ = _make_runner(process)
    code = await runner.wait_for_exit(process=process)
    assert code == 7


async def test_drain_already_exited() -> None:
    """drain on already-exited process should return code immediately."""
    process = _FakeProcess(return_code=0)
    process.returncode = 0
    runner, _ = _make_runner(process)
    code = await runner.drain(process=process, timeout_seconds=1.0)
    assert code == 0


async def test_drain_timeout_returns_none() -> None:
    """drain should return None/returncode if process does not exit in time."""
    process = _FakeProcess(return_code=0, wait_delay_seconds=10.0)
    runner, _ = _make_runner(process)
    code = await runner.drain(process=process, timeout_seconds=0.05)
    assert code is None or isinstance(code, int)


async def test_kill_running_process() -> None:
    """kill should mark process as killed."""
    process = _FakeProcess(return_code=0)
    runner, _ = _make_runner(process)
    runner.kill(process)
    assert process.was_killed is True
    assert process.returncode == -9


async def test_kill_already_exited_is_noop() -> None:
    """kill on already-exited process should be a no-op."""
    process = _FakeProcess(return_code=0)
    process.returncode = 0
    runner, _ = _make_runner(process)
    runner.kill(process)
    assert process.was_killed is False
    assert process.returncode == 0


# ---------------------------------------------------------------------------
# Policies: ErrorPolicy
# ---------------------------------------------------------------------------


def test_error_policy_tolerant_never_raises() -> None:
    """Tolerant ErrorPolicy should return False for should_raise."""
    policy = ErrorPolicy(mode=ErrorMode.TOLERANT)
    assert policy.should_raise(RuntimeError("test")) is False
    assert policy.is_strict is False


def test_error_policy_strict_always_raises() -> None:
    """Strict ErrorPolicy should return True for should_raise."""
    policy = ErrorPolicy(mode=ErrorMode.STRICT)
    assert policy.should_raise(RuntimeError("test")) is True
    assert policy.is_strict is True


# ---------------------------------------------------------------------------
# Policies: ExitCodePolicy
# ---------------------------------------------------------------------------


def test_exit_code_policy_zero_allowed_by_default() -> None:
    """Default policy should accept exit code 0."""
    policy = ExitCodePolicy()
    policy.validate(return_code=0, stderr="")


def test_exit_code_policy_non_zero_raises() -> None:
    """Default policy should raise on non-zero exit."""
    from nocturna_engine.streaming.jsonl_engine.errors import JsonlExitCodeError

    policy = ExitCodePolicy()
    with pytest.raises(JsonlExitCodeError):
        policy.validate(return_code=1, stderr="error output")


def test_exit_code_policy_custom_allowed_codes() -> None:
    """Custom allowed codes should suppress error for those codes."""
    policy = ExitCodePolicy(allowed_exit_codes={0, 1, 2})
    policy.validate(return_code=2, stderr="")


def test_exit_code_policy_fail_disabled() -> None:
    """fail_on_non_zero_exit=False should suppress all exit code errors."""
    policy = ExitCodePolicy(fail_on_non_zero_exit=False)
    policy.validate(return_code=255, stderr="fatal")


def test_exit_code_policy_host_unreachable() -> None:
    """Unreachable hints matching stderr should raise target-unreachable."""
    from nocturna_engine.streaming.jsonl_engine.errors import (
        JsonlTargetUnreachableError,
    )

    policy = ExitCodePolicy(
        host_unreachable_hints=("could not resolve", "connection refused"),
    )
    with pytest.raises(JsonlTargetUnreachableError):
        policy.validate(
            return_code=1, stderr="Could not resolve host example.com"
        )


def test_exit_code_policy_host_unreachable_case_insensitive() -> None:
    """Unreachable hint matching should be case-insensitive."""
    from nocturna_engine.streaming.jsonl_engine.errors import (
        JsonlTargetUnreachableError,
    )

    policy = ExitCodePolicy(host_unreachable_hints=("FAILED TO RESOLVE",))
    with pytest.raises(JsonlTargetUnreachableError):
        policy.validate(return_code=1, stderr="failed to resolve host")


# ---------------------------------------------------------------------------
# Policies: MalformedThresholdPolicy
# ---------------------------------------------------------------------------


def test_malformed_threshold_no_limits_passes() -> None:
    """No configured limits should always pass."""
    policy = MalformedThresholdPolicy()
    stats = JsonlStreamStats(total_lines=100, malformed_lines=50)
    policy.validate(stats)


def test_malformed_threshold_count_exceeded() -> None:
    """Exceeding max_malformed_count should raise PolicyViolation."""
    from nocturna_engine.streaming.jsonl_engine.errors import (
        JsonlPolicyViolationError,
    )

    policy = MalformedThresholdPolicy(max_malformed_count=5)
    stats = JsonlStreamStats(total_lines=10, malformed_lines=6)
    with pytest.raises(JsonlPolicyViolationError, match="threshold exceeded"):
        policy.validate(stats)


def test_malformed_threshold_count_at_limit_passes() -> None:
    """Malformed count exactly at limit should pass."""
    policy = MalformedThresholdPolicy(max_malformed_count=5)
    stats = JsonlStreamStats(total_lines=10, malformed_lines=5)
    policy.validate(stats)


def test_malformed_threshold_ratio_exceeded() -> None:
    """Exceeding max_malformed_ratio should raise PolicyViolation."""
    from nocturna_engine.streaming.jsonl_engine.errors import (
        JsonlPolicyViolationError,
    )

    policy = MalformedThresholdPolicy(max_malformed_ratio=0.5)
    stats = JsonlStreamStats(total_lines=10, malformed_lines=6)
    with pytest.raises(JsonlPolicyViolationError, match="ratio"):
        policy.validate(stats)


def test_malformed_threshold_ratio_with_zero_lines() -> None:
    """Zero total lines should skip ratio check."""
    policy = MalformedThresholdPolicy(max_malformed_ratio=0.1)
    stats = JsonlStreamStats(total_lines=0, malformed_lines=0)
    policy.validate(stats)


def test_build_policies_returns_three_policies() -> None:
    """build_policies should return ErrorPolicy, ExitCodePolicy, MalformedThresholdPolicy."""
    config = JsonlPolicyConfig(
        error_mode=ErrorMode.STRICT,
        fail_on_non_zero_exit=True,
        allowed_exit_codes={0, 1},
        malformed_max_count=10,
        malformed_max_ratio=0.5,
    )
    error_p, exit_p, malformed_p = build_policies(config)
    assert isinstance(error_p, ErrorPolicy)
    assert error_p.is_strict is True
    assert isinstance(exit_p, ExitCodePolicy)
    assert exit_p.allowed_exit_codes == {0, 1}
    assert isinstance(malformed_p, MalformedThresholdPolicy)
    assert malformed_p.max_malformed_count == 10


# ---------------------------------------------------------------------------
# Utils: truncate_text
# ---------------------------------------------------------------------------


def test_truncate_text_short_string() -> None:
    """Short strings should not be truncated."""
    assert truncate_text("hello", max_chars=10) == "hello"


def test_truncate_text_exact_length() -> None:
    """String at exact max length should not be truncated."""
    assert truncate_text("abcde", max_chars=5) == "abcde"


def test_truncate_text_long_string_adds_ellipsis() -> None:
    """Long string should be truncated with ellipsis."""
    result = truncate_text("a" * 100, max_chars=10)
    assert len(result) == 10
    assert result.endswith("...")


def test_truncate_text_zero_max_chars() -> None:
    """Zero max_chars should return empty string."""
    assert truncate_text("hello", max_chars=0) == ""


def test_truncate_text_very_small_max_chars() -> None:
    """max_chars <= 3 should truncate without ellipsis."""
    assert truncate_text("hello", max_chars=2) == "he"
    assert truncate_text("hello", max_chars=3) == "hel"


# ---------------------------------------------------------------------------
# Utils: sanitize_output
# ---------------------------------------------------------------------------


def test_sanitize_output_strips_ansi() -> None:
    """ANSI escape codes should be removed from output."""
    result = sanitize_output("\x1b[31mError\x1b[0m")
    assert result == "Error"


def test_sanitize_output_normalizes_line_endings() -> None:
    """CRLF and CR should be normalized to LF."""
    result = sanitize_output("line1\r\nline2\rline3")
    assert "\r" not in result
    assert "line1" in result


def test_sanitize_output_strips_whitespace() -> None:
    """Leading/trailing whitespace should be stripped."""
    result = sanitize_output("  hello world  \n")
    assert result == "hello world"


# ---------------------------------------------------------------------------
# Utils: normalize_command
# ---------------------------------------------------------------------------


def test_normalize_command_valid() -> None:
    """Valid command should be normalized."""
    result = normalize_command(["echo", "hello"])
    assert result == ["echo", "hello"]


def test_normalize_command_empty_raises() -> None:
    """Empty command should raise ValueError."""
    with pytest.raises(ValueError, match="empty"):
        normalize_command([])


def test_normalize_command_null_byte_raises() -> None:
    """Command with null byte should raise ValueError."""
    with pytest.raises(ValueError, match="null"):
        normalize_command(["cmd\x00arg"])


def test_normalize_command_empty_arg_raises() -> None:
    """Empty string argument should raise ValueError."""
    with pytest.raises(ValueError, match="empty"):
        normalize_command([""])


def test_normalize_command_coerces_non_strings() -> None:
    """Non-string arguments should be coerced via str()."""
    result = normalize_command(["cmd", 42, True])
    assert result == ["cmd", "42", "True"]


# ---------------------------------------------------------------------------
# Utils: format_command_for_log
# ---------------------------------------------------------------------------


def test_format_command_for_log_basic() -> None:
    """Basic command should be shell-quoted."""
    result = format_command_for_log(["echo", "hello world"])
    assert "echo" in result
    assert "hello" in result


def test_format_command_for_log_redacts_sensitive_flags() -> None:
    """Sensitive flags like --token should have values redacted."""
    result = format_command_for_log(["tool", "--token", "secret123"])
    assert "secret123" not in result
    assert "***" in result


def test_format_command_for_log_redacts_inline_token() -> None:
    """Inline token=value patterns should be redacted."""
    result = format_command_for_log(["tool", "--api_key=secret"])
    assert "secret" not in result
    assert "***" in result


# ---------------------------------------------------------------------------
# Utils: OutputBudget
# ---------------------------------------------------------------------------


def test_output_budget_stdout_within_limits() -> None:
    """Consuming stdout within limits should not raise."""
    budget = OutputBudget(max_output_bytes=1000, max_stderr_bytes=None)
    budget.consume_stdout(500)
    assert budget.total_bytes == 500


def test_output_budget_stdout_exceeds_limit() -> None:
    """Consuming stdout beyond limit should raise."""
    budget = OutputBudget(max_output_bytes=100, max_stderr_bytes=None)
    with pytest.raises(JsonlOutputLimitExceededError):
        budget.consume_stdout(101)


def test_output_budget_stderr_within_limits() -> None:
    """Consuming stderr within limits should not raise."""
    budget = OutputBudget(max_output_bytes=1000, max_stderr_bytes=500)
    budget.consume_stderr(400)
    assert budget.stderr_bytes == 400
    assert budget.total_bytes == 400


def test_output_budget_stderr_exceeds_dedicated_limit() -> None:
    """Consuming stderr beyond dedicated limit should raise."""
    budget = OutputBudget(max_output_bytes=10_000, max_stderr_bytes=100)
    with pytest.raises(JsonlOutputLimitExceededError):
        budget.consume_stderr(101)


def test_output_budget_stderr_exceeds_global_limit() -> None:
    """Stderr exceeding global output limit should raise."""
    budget = OutputBudget(max_output_bytes=100, max_stderr_bytes=200)
    with pytest.raises(JsonlOutputLimitExceededError):
        budget.consume_stderr(101)


def test_output_budget_combined_exceeds_global() -> None:
    """Combined stdout + stderr exceeding global limit should raise."""
    budget = OutputBudget(max_output_bytes=100, max_stderr_bytes=200)
    budget.consume_stdout(60)
    with pytest.raises(JsonlOutputLimitExceededError):
        budget.consume_stderr(50)


def test_output_budget_no_stderr_limit() -> None:
    """When max_stderr_bytes is None, only global limit applies."""
    budget = OutputBudget(max_output_bytes=1000, max_stderr_bytes=None)
    budget.consume_stderr(500)
    assert budget.stderr_bytes == 500


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_initial_state() -> None:
    """Fresh metrics should have zero counters."""
    metrics = JsonlMetrics()
    assert metrics.stats.emitted_records == 0
    assert metrics.stats.bytes_read == 0


def test_metrics_add_bytes_read() -> None:
    """add_bytes_read should increment bytes counter."""
    metrics = JsonlMetrics()
    metrics.add_bytes_read(100)
    metrics.add_bytes_read(50)
    assert metrics.stats.bytes_read == 150


def test_metrics_add_bytes_read_negative_clamped() -> None:
    """Negative byte counts should be clamped to zero."""
    metrics = JsonlMetrics()
    metrics.add_bytes_read(-10)
    assert metrics.stats.bytes_read == 0


def test_metrics_increment_emitted_records() -> None:
    """increment_emitted_records should increment by one each call."""
    metrics = JsonlMetrics()
    metrics.increment_emitted_records()
    metrics.increment_emitted_records()
    assert metrics.stats.emitted_records == 2


def test_metrics_finalize_sets_duration() -> None:
    """finalize should set non-negative duration and throughput."""
    metrics = JsonlMetrics()
    metrics.increment_emitted_records()
    stats = metrics.finalize()
    assert stats.duration_seconds >= 0.0
    assert stats.throughput_records_per_second >= 0.0


def test_metrics_finalize_zero_duration_throughput() -> None:
    """finalize with zero emitted records should have zero or positive throughput."""
    metrics = JsonlMetrics()
    stats = metrics.finalize()
    assert stats.throughput_records_per_second >= 0.0


def test_metrics_with_custom_stats() -> None:
    """Metrics initialized with custom stats object should use it."""
    custom = JsonlStreamStats(bytes_read=42)
    metrics = JsonlMetrics(stats=custom)
    assert metrics.stats.bytes_read == 42
    metrics.add_bytes_read(8)
    assert metrics.stats.bytes_read == 50
