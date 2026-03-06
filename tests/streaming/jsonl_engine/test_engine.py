"""Comprehensive edge-case tests for the JSONL streaming engine facade."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from nocturna_engine.streaming.jsonl_engine import (
    EngineErrorKind,
    ErrorMode,
    JsonlEngineConfig,
    JsonlEngineHooks,
    JsonlEngineResult,
    JsonlHeartbeatConfig,
    JsonlIssueEnvelope,
    JsonlOutputLimits,
    JsonlParserConfig,
    JsonlPolicyConfig,
    JsonlRecordEnvelope,
    JsonlStreamStats,
    JsonlStreamingEngine,
    compose_hooks,
)
from nocturna_engine.streaming.jsonl_engine.runner import JsonlSubprocessRunner


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeStream:
    """Deterministic async byte stream for stdout/stderr tests."""

    def __init__(self, chunks: list[bytes], *, delay_seconds: float = 0.0) -> None:
        self._chunks = list(chunks)
        self._delay_seconds = delay_seconds

    async def read(self, _size: int = -1) -> bytes:
        if self._delay_seconds > 0:
            await asyncio.sleep(self._delay_seconds)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _FakeProcess:
    """Subprocess test double implementing protocol used by runner."""

    def __init__(
        self,
        *,
        stdout_chunks: list[bytes],
        stderr_chunks: list[bytes],
        return_code: int,
        wait_delay_seconds: float = 0.0,
        stream_delay_seconds: float = 0.0,
    ) -> None:
        self.stdout = _FakeStream(stdout_chunks, delay_seconds=stream_delay_seconds)
        self.stderr = _FakeStream(stderr_chunks, delay_seconds=stream_delay_seconds)
        self.returncode: int | None = None
        self._return_code = return_code
        self._wait_delay_seconds = wait_delay_seconds
        self.was_killed = False

    async def wait(self) -> int:
        if self.returncode is None and self._wait_delay_seconds > 0:
            remaining = self._wait_delay_seconds
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


def _build_engine(process: _FakeProcess) -> tuple[JsonlStreamingEngine, list[list[str]]]:
    """Build engine with fake process factory and command capture."""
    commands: list[list[str]] = []

    async def _factory(command: list[str]) -> _FakeProcess:
        commands.append(list(command))
        return process

    runner = JsonlSubprocessRunner(process_factory=_factory, chunk_size=64)
    return JsonlStreamingEngine(runner=runner), commands


def _build_config(**overrides: Any) -> JsonlEngineConfig:
    """Build baseline engine config for tests."""
    config = JsonlEngineConfig(
        command=["fake-jsonl-tool", "--jsonl"],
        timeout_seconds=2.0,
        queue_maxsize=64,
        collect_records=True,
        parser=JsonlParserConfig(max_line_bytes=1024, chunk_size=64),
        limits=JsonlOutputLimits(max_output_bytes=2 * 1024 * 1024, max_stderr_bytes=512 * 1024),
        heartbeat=JsonlHeartbeatConfig(every_records=50, every_seconds=None),
        policies=JsonlPolicyConfig(error_mode=ErrorMode.TOLERANT),
    )
    return config.model_copy(update=overrides)


# ---------------------------------------------------------------------------
# Engine lifecycle tests
# ---------------------------------------------------------------------------

async def test_engine_happy_path_jsonl() -> None:
    """Engine should parse valid JSONL stream and emit hooks/records."""
    process = _FakeProcess(
        stdout_chunks=[b'{"id":1}\n{"id"', b":2}\n"],
        stderr_chunks=[],
        return_code=0,
    )
    engine, commands = _build_engine(process)
    seen_records: list[int] = []

    async def on_record(envelope: JsonlRecordEnvelope) -> None:
        seen_records.append(int(envelope.payload["id"]))

    result = await engine.run(
        config=_build_config(),
        hooks=JsonlEngineHooks(on_record=on_record),
    )

    assert commands == [["fake-jsonl-tool", "--jsonl"]]
    assert result.error is None
    assert result.return_code == 0
    assert [r["id"] for r in result.records] == [1, 2]
    assert seen_records == [1, 2]
    assert result.stats.total_lines == 2
    assert result.stats.parsed_lines == 2
    assert result.stats.emitted_records == 2
    assert result.stats.bytes_read > 0


async def test_engine_empty_stdout_returns_empty_records() -> None:
    """Empty stdout should produce zero records with no error."""
    process = _FakeProcess(stdout_chunks=[], stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config())

    assert result.error is None
    assert result.records == []
    assert result.stats.total_lines == 0
    assert result.stats.emitted_records == 0


async def test_engine_only_empty_lines_produces_no_records() -> None:
    """Stdout with only whitespace/empty lines should yield zero records."""
    process = _FakeProcess(
        stdout_chunks=[b"\n\n   \n\n"],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config())

    assert result.error is None
    assert result.records == []


async def test_engine_collect_records_false_omits_payload_collection() -> None:
    """collect_records=False should still emit hooks but not accumulate records."""
    process = _FakeProcess(
        stdout_chunks=[b'{"id":1}\n{"id":2}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    seen: list[int] = []

    async def on_record(env: JsonlRecordEnvelope) -> None:
        seen.append(env.payload["id"])

    result = await engine.run(
        config=_build_config(collect_records=False),
        hooks=JsonlEngineHooks(on_record=on_record),
    )

    assert result.error is None
    assert result.records == []
    assert seen == [1, 2]


async def test_engine_reports_timeout() -> None:
    """Timeout should kill process and return timeout error kind."""
    process = _FakeProcess(
        stdout_chunks=[],
        stderr_chunks=[],
        return_code=0,
        wait_delay_seconds=10.0,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config(timeout_seconds=0.05))

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.TIMEOUT
    assert process.was_killed is True


async def test_engine_cancellation_returns_cancelled_result() -> None:
    """External cancellation signal should stop run and kill process."""
    lines = [b'{"ok":1}\n' for _ in range(200)]
    process = _FakeProcess(
        stdout_chunks=lines,
        stderr_chunks=[],
        return_code=0,
        wait_delay_seconds=5.0,
        stream_delay_seconds=0.01,
    )
    engine, _ = _build_engine(process)
    cancel_event = asyncio.Event()

    task = asyncio.create_task(
        engine.run(
            config=_build_config(timeout_seconds=10.0),
            cancel_event=cancel_event,
        )
    )
    await asyncio.sleep(0.05)
    cancel_event.set()
    result = await task

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.CANCELLED
    assert process.was_killed is True


async def test_engine_cancellation_before_start_stops_immediately() -> None:
    """Setting cancel event before run should finish fast with cancelled error."""
    process = _FakeProcess(
        stdout_chunks=[b'{"id":1}\n'],
        stderr_chunks=[],
        return_code=0,
        wait_delay_seconds=5.0,
        stream_delay_seconds=0.1,
    )
    engine, _ = _build_engine(process)
    cancel_event = asyncio.Event()
    cancel_event.set()

    result = await engine.run(
        config=_build_config(timeout_seconds=5.0),
        cancel_event=cancel_event,
    )

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.CANCELLED


# ---------------------------------------------------------------------------
# Error handling / policy tests
# ---------------------------------------------------------------------------

async def test_engine_tolerant_mode_skips_broken_json_lines() -> None:
    """Tolerant mode should skip malformed lines and continue streaming."""
    process = _FakeProcess(
        stdout_chunks=[b'{"ok":1}\n{broken}\n{"ok":2}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(policies=JsonlPolicyConfig(error_mode=ErrorMode.TOLERANT))
    )

    assert result.error is None
    assert [r["ok"] for r in result.records] == [1, 2]
    assert result.stats.malformed_lines == 1
    assert result.stats.skipped_lines == 1


async def test_engine_strict_mode_fails_on_first_malformed_line() -> None:
    """Strict mode should stop when malformed JSON is encountered."""
    process = _FakeProcess(
        stdout_chunks=[b'{"ok":1}\n{broken}\n{"ok":2}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(policies=JsonlPolicyConfig(error_mode=ErrorMode.STRICT))
    )

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.MALFORMED_LINE


async def test_engine_marks_oversized_line_and_continues_in_tolerant_mode() -> None:
    """Oversized lines should be skipped and counted without aborting."""
    oversized = b"x" * 2048 + b"\n"
    process = _FakeProcess(
        stdout_chunks=[oversized + b'{"ok":1}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(
            parser=JsonlParserConfig(max_line_bytes=512, chunk_size=128),
            policies=JsonlPolicyConfig(error_mode=ErrorMode.TOLERANT),
        )
    )

    assert result.error is None
    assert result.stats.oversized_lines == 1
    assert result.stats.parsed_lines == 1
    assert result.records == [{"ok": 1}]


async def test_engine_reports_non_zero_exit_code() -> None:
    """Disallowed non-zero exit code should be returned as error."""
    process = _FakeProcess(
        stdout_chunks=[],
        stderr_chunks=[b"boom\n"],
        return_code=3,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config())

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.NON_ZERO_EXIT
    assert result.return_code == 3


async def test_engine_allowed_exit_codes_bypass_error() -> None:
    """Exit codes in allowed set should not raise error."""
    process = _FakeProcess(
        stdout_chunks=[b'{"ok":1}\n'],
        stderr_chunks=[],
        return_code=2,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(
            policies=JsonlPolicyConfig(allowed_exit_codes={0, 2})
        )
    )

    assert result.error is None
    assert result.return_code == 2


async def test_engine_fail_on_non_zero_exit_disabled() -> None:
    """fail_on_non_zero_exit=False should suppress exit code errors."""
    process = _FakeProcess(
        stdout_chunks=[b'{"ok":1}\n'],
        stderr_chunks=[b"warning\n"],
        return_code=42,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(
            policies=JsonlPolicyConfig(fail_on_non_zero_exit=False)
        )
    )

    assert result.error is None
    assert result.return_code == 42


async def test_engine_applies_host_unreachable_stderr_policy() -> None:
    """Configured unreachable hints should map to target-unreachable error."""
    process = _FakeProcess(
        stdout_chunks=[],
        stderr_chunks=[b"failed to resolve host\n"],
        return_code=1,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(
            policies=JsonlPolicyConfig(
                host_unreachable_hints=("failed to resolve host",),
            )
        )
    )

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.TARGET_UNREACHABLE


async def test_engine_malformed_threshold_count_triggers_policy_violation() -> None:
    """Exceeding malformed_max_count should trigger policy error."""
    payload = b'{"ok":1}\n{bad1}\n{bad2}\n{bad3}\n{"ok":2}\n'
    process = _FakeProcess(stdout_chunks=[payload], stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(
            policies=JsonlPolicyConfig(
                error_mode=ErrorMode.TOLERANT,
                malformed_max_count=2,
            )
        )
    )

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.POLICY


async def test_engine_malformed_threshold_ratio_triggers_policy_violation() -> None:
    """Exceeding malformed_max_ratio should trigger policy error."""
    payload = b'{bad1}\n{bad2}\n{bad3}\n{"ok":1}\n'
    process = _FakeProcess(stdout_chunks=[payload], stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(
            policies=JsonlPolicyConfig(
                error_mode=ErrorMode.TOLERANT,
                malformed_max_ratio=0.5,
            )
        )
    )

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.POLICY


# ---------------------------------------------------------------------------
# Hooks / callbacks
# ---------------------------------------------------------------------------

async def test_engine_on_error_hook_called_for_malformed_lines() -> None:
    """on_error hook should receive issue envelopes for malformed lines."""
    process = _FakeProcess(
        stdout_chunks=[b'{"ok":1}\n{broken}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    issues: list[JsonlIssueEnvelope] = []

    async def on_error(issue: JsonlIssueEnvelope) -> None:
        issues.append(issue)

    result = await engine.run(
        config=_build_config(),
        hooks=JsonlEngineHooks(on_error=on_error),
    )

    assert result.error is None
    assert len(issues) == 1
    assert issues[0].source == "stdout"


async def test_engine_on_complete_hook_receives_final_result() -> None:
    """on_complete hook should receive the final result object."""
    process = _FakeProcess(
        stdout_chunks=[b'{"id":1}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    results: list[JsonlEngineResult] = []

    async def on_complete(r: JsonlEngineResult) -> None:
        results.append(r)

    await engine.run(
        config=_build_config(),
        hooks=JsonlEngineHooks(on_complete=on_complete),
    )

    assert len(results) == 1
    assert results[0].return_code == 0


async def test_engine_hook_failure_in_strict_mode_sets_error() -> None:
    """Failing on_record hook in strict mode should result in hook error."""
    process = _FakeProcess(
        stdout_chunks=[b'{"id":1}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)

    async def bad_hook(env: JsonlRecordEnvelope) -> None:
        raise RuntimeError("boom")

    result = await engine.run(
        config=_build_config(
            policies=JsonlPolicyConfig(error_mode=ErrorMode.STRICT)
        ),
        hooks=JsonlEngineHooks(on_record=bad_hook),
    )

    assert result.error is not None
    assert result.error_kind == EngineErrorKind.HOOK_FAILURE


async def test_engine_hook_failure_in_tolerant_mode_continues() -> None:
    """Failing on_record hook in tolerant mode should not abort the run."""
    process = _FakeProcess(
        stdout_chunks=[b'{"id":1}\n{"id":2}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    call_count = 0

    async def bad_hook(env: JsonlRecordEnvelope) -> None:
        nonlocal call_count
        call_count += 1
        raise RuntimeError("boom")

    result = await engine.run(
        config=_build_config(
            policies=JsonlPolicyConfig(error_mode=ErrorMode.TOLERANT)
        ),
        hooks=JsonlEngineHooks(on_record=bad_hook),
    )

    # Tolerant mode: both records attempted; hook failures logged but not fatal
    assert result.error is None


async def test_compose_hooks_empty_returns_noop_hooks() -> None:
    """compose_hooks with no args should return empty hooks."""
    composed = compose_hooks()
    assert composed.on_record is None
    assert composed.on_error is None


async def test_compose_hooks_single_passthrough() -> None:
    """compose_hooks with one hook should return it directly."""
    hook = JsonlEngineHooks(on_record=lambda env: None)
    composed = compose_hooks(hook)
    assert composed is hook


async def test_compose_hooks_merges_multiple() -> None:
    """compose_hooks should call all hooks in order."""
    calls: list[str] = []

    async def hook_a(env: JsonlRecordEnvelope) -> None:
        calls.append("a")

    async def hook_b(env: JsonlRecordEnvelope) -> None:
        calls.append("b")

    composed = compose_hooks(
        JsonlEngineHooks(on_record=hook_a),
        None,
        JsonlEngineHooks(on_record=hook_b),
    )
    env = JsonlRecordEnvelope(line_number=1, raw_line='{"x":1}', payload={"x": 1})
    await composed.emit_record(env)
    assert calls == ["a", "b"]


# ---------------------------------------------------------------------------
# Backpressure / large payloads
# ---------------------------------------------------------------------------

async def test_engine_handles_backpressure_with_small_queue() -> None:
    """Small queue with slow consumer should still complete safely."""
    total = 300
    payload = b"".join(
        (json.dumps({"index": idx}) + "\n").encode("utf-8")
        for idx in range(total)
    )
    chunks = [payload[i : i + 17] for i in range(0, len(payload), 17)]
    process = _FakeProcess(stdout_chunks=chunks, stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)

    async def slow_hook(_: JsonlRecordEnvelope) -> None:
        await asyncio.sleep(0.0005)

    result = await engine.run(
        config=_build_config(queue_maxsize=1, timeout_seconds=10.0),
        hooks=JsonlEngineHooks(on_record=slow_hook),
    )

    assert result.error is None
    assert len(result.records) == total
    assert result.stats.emitted_records == total


async def test_engine_large_single_json_object() -> None:
    """A single very large JSON object should parse when within line limit."""
    big_payload = {"key": "x" * 50_000}
    line = json.dumps(big_payload).encode("utf-8") + b"\n"
    process = _FakeProcess(
        stdout_chunks=[line],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(
        config=_build_config(
            parser=JsonlParserConfig(max_line_bytes=200_000, chunk_size=8192),
        )
    )

    assert result.error is None
    assert len(result.records) == 1
    assert result.records[0]["key"] == "x" * 50_000


# ---------------------------------------------------------------------------
# iter_records streaming iterator
# ---------------------------------------------------------------------------

async def test_iter_records_yields_all_records() -> None:
    """iter_records should yield every parsed envelope."""
    process = _FakeProcess(
        stdout_chunks=[b'{"a":1}\n{"a":2}\n{"a":3}\n'],
        stderr_chunks=[],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    collected: list[dict[str, Any]] = []

    async for envelope in engine.iter_records(config=_build_config()):
        collected.append(envelope.payload)

    assert collected == [{"a": 1}, {"a": 2}, {"a": 3}]


async def test_iter_records_empty_stream() -> None:
    """iter_records on empty stdout should yield nothing."""
    process = _FakeProcess(stdout_chunks=[], stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)
    collected: list[dict[str, Any]] = []

    async for envelope in engine.iter_records(config=_build_config()):
        collected.append(envelope.payload)

    assert collected == []


async def test_iter_records_cancellation_stops_iteration() -> None:
    """Cancelling during iter_records should stop iteration cleanly."""
    process = _FakeProcess(
        stdout_chunks=[b'{"ok":1}\n' for _ in range(100)],
        stderr_chunks=[],
        return_code=0,
        stream_delay_seconds=0.01,
        wait_delay_seconds=5.0,
    )
    engine, _ = _build_engine(process)
    cancel_event = asyncio.Event()
    collected: list[dict[str, Any]] = []

    async def _iterate() -> None:
        async for envelope in engine.iter_records(
            config=_build_config(timeout_seconds=10.0),
            cancel_event=cancel_event,
        ):
            collected.append(envelope.payload)

    task = asyncio.create_task(_iterate())
    await asyncio.sleep(0.05)
    cancel_event.set()
    await asyncio.wait_for(task, timeout=3.0)

    # Should have collected some but not all records
    assert len(collected) < 100


# ---------------------------------------------------------------------------
# Unicode / encoding edge cases
# ---------------------------------------------------------------------------

async def test_engine_unicode_records() -> None:
    """Unicode characters in JSONL should be parsed correctly."""
    line = json.dumps({"emoji": "🎉", "cjk": "日本語"}).encode("utf-8") + b"\n"
    process = _FakeProcess(stdout_chunks=[line], stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config())

    assert result.error is None
    assert result.records[0]["emoji"] == "🎉"
    assert result.records[0]["cjk"] == "日本語"


async def test_engine_handles_stderr_with_ansi_escapes() -> None:
    """Stderr with ANSI escape codes should be sanitized in result."""
    process = _FakeProcess(
        stdout_chunks=[b'{"ok":1}\n'],
        stderr_chunks=[b"\x1b[31mError: something\x1b[0m\n"],
        return_code=0,
    )
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config())

    assert result.error is None
    assert "\x1b" not in result.stderr
    assert "Error: something" in result.stderr


# ---------------------------------------------------------------------------
# Duration / throughput metrics
# ---------------------------------------------------------------------------

async def test_engine_result_has_nonnegative_duration() -> None:
    """Result duration_seconds should always be non-negative."""
    process = _FakeProcess(stdout_chunks=[], stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config())

    assert result.duration_seconds >= 0.0
    assert result.stats.duration_seconds >= 0.0


async def test_engine_result_was_cancelled_flag() -> None:
    """was_cancelled should be True when engine is cancelled, False otherwise."""
    # Non-cancelled case
    process = _FakeProcess(stdout_chunks=[], stderr_chunks=[], return_code=0)
    engine, _ = _build_engine(process)
    result = await engine.run(config=_build_config())
    assert result.was_cancelled is False

    # Cancelled case
    process2 = _FakeProcess(
        stdout_chunks=[],
        stderr_chunks=[],
        return_code=0,
        wait_delay_seconds=5.0,
    )
    engine2, _ = _build_engine(process2)
    cancel = asyncio.Event()
    cancel.set()
    result2 = await engine2.run(
        config=_build_config(timeout_seconds=5.0),
        cancel_event=cancel,
    )
    assert result2.was_cancelled is True
