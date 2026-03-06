"""Edge-case tests for nocturna_engine.utils.async_helpers."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from nocturna_engine.exceptions import NocturnaTimeoutError
from nocturna_engine.utils.async_helpers import (
    bounded_gather,
    retry_async,
    with_timeout,
)


# ---------------------------------------------------------------------------
# with_timeout
# ---------------------------------------------------------------------------


class TestWithTimeout:
    """Edge cases for with_timeout."""

    async def test_instant_completion_within_tiny_timeout(self) -> None:
        """An already-resolved coroutine finishes even with very small timeout."""

        async def instant() -> str:
            return "done"

        result = await with_timeout(instant(), timeout_seconds=0.001, operation_name="instant")
        assert result == "done"

    async def test_exact_timeout_boundary_slow_op_raises(self) -> None:
        """Operation taking longer than timeout triggers NocturnaTimeoutError."""

        async def slow() -> str:
            await asyncio.sleep(5.0)
            return "never"

        with pytest.raises(NocturnaTimeoutError, match="timed out"):
            await with_timeout(slow(), timeout_seconds=0.05, operation_name="slow")

    async def test_zero_timeout_raises_for_any_awaitable(self) -> None:
        """Zero timeout should raise immediately for non-resolved awaitables."""

        async def trivial() -> str:
            await asyncio.sleep(0)  # yields control
            return "x"

        with pytest.raises(NocturnaTimeoutError):
            await with_timeout(trivial(), timeout_seconds=0.0, operation_name="zero")

    async def test_negative_timeout_raises(self) -> None:
        """Negative timeout should raise (asyncio treats it as expired)."""

        async def trivial() -> str:
            await asyncio.sleep(0)
            return "x"

        with pytest.raises((NocturnaTimeoutError, ValueError)):
            await with_timeout(trivial(), timeout_seconds=-1.0, operation_name="neg")

    async def test_error_message_contains_operation_name(self) -> None:
        async def slow() -> None:
            await asyncio.sleep(10)

        with pytest.raises(NocturnaTimeoutError, match="my_op"):
            await with_timeout(slow(), timeout_seconds=0.01, operation_name="my_op")

    async def test_error_message_contains_formatted_timeout(self) -> None:
        async def slow() -> None:
            await asyncio.sleep(10)

        with pytest.raises(NocturnaTimeoutError, match=r"0\.01s"):
            await with_timeout(slow(), timeout_seconds=0.01, operation_name="op")

    async def test_timeout_error_chains_original_timeout_error(self) -> None:
        """NocturnaTimeoutError.__cause__ should be the original TimeoutError."""

        async def slow() -> None:
            await asyncio.sleep(10)

        with pytest.raises(NocturnaTimeoutError) as exc_info:
            await with_timeout(slow(), timeout_seconds=0.01, operation_name="op")

        assert isinstance(exc_info.value.__cause__, TimeoutError)

    async def test_returns_none_when_operation_returns_none(self) -> None:
        async def noop() -> None:
            pass

        result = await with_timeout(noop(), timeout_seconds=1.0, operation_name="noop")
        assert result is None

    async def test_propagates_non_timeout_exception(self) -> None:
        """Non-timeout exceptions pass through unwrapped."""

        async def explode() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await with_timeout(explode(), timeout_seconds=5.0, operation_name="explode")


# ---------------------------------------------------------------------------
# retry_async
# ---------------------------------------------------------------------------


class TestRetryAsync:
    """Edge cases for retry_async."""

    async def test_zero_retries_raises_on_first_failure(self) -> None:
        call_count = 0

        async def failing() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError("fail")

        with pytest.raises(ValueError, match="fail"):
            await retry_async(failing, retries=0)

        assert call_count == 1

    async def test_retries_exhausted_raises_last_exception(self) -> None:
        call_count = 0

        async def failing() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError(f"attempt_{call_count}")

        with pytest.raises(ValueError, match="attempt_3"):
            await retry_async(failing, retries=2, base_delay=0.01, max_delay=0.01, jitter=0.0)

        assert call_count == 3  # 1 initial + 2 retries

    async def test_succeeds_on_last_retry(self) -> None:
        call_count = 0

        async def flaky() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("not yet")
            return "ok"

        result = await retry_async(flaky, retries=2, base_delay=0.01, max_delay=0.01, jitter=0.0)
        assert result == "ok"
        assert call_count == 3

    async def test_non_retryable_exception_not_retried(self) -> None:
        call_count = 0

        async def failing() -> None:
            nonlocal call_count
            call_count += 1
            raise TypeError("wrong type")

        with pytest.raises(TypeError):
            await retry_async(failing, retries=5, retry_exceptions=(ValueError,), base_delay=0.01)

        assert call_count == 1

    async def test_exponential_backoff_respects_max_delay(self) -> None:
        """With many retries and a low max_delay, delays are capped."""
        call_count = 0
        timestamps: list[float] = []

        async def failing() -> None:
            nonlocal call_count
            timestamps.append(time.monotonic())
            call_count += 1
            raise ValueError("fail")

        with pytest.raises(ValueError):
            await retry_async(
                failing,
                retries=4,
                base_delay=0.01,
                max_delay=0.02,
                jitter=0.0,
            )

        # Verify no delay between calls exceeds max_delay + reasonable tolerance
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i - 1]
            assert gap < 0.15, f"Gap {gap:.3f}s exceeds max_delay+tolerance"

    async def test_jitter_stays_within_bounds(self) -> None:
        """Delays include jitter in [0, jitter_value] range."""
        timestamps: list[float] = []

        async def failing() -> None:
            timestamps.append(time.monotonic())
            raise ValueError("fail")

        with pytest.raises(ValueError):
            await retry_async(
                failing,
                retries=5,
                base_delay=0.01,
                max_delay=0.01,
                jitter=0.02,
            )

        # Each gap should be base_delay + [0, jitter] = [0.01, 0.03] + OS overhead
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i - 1]
            assert gap >= 0.005, f"Gap {gap:.4f}s suspiciously small"
            assert gap < 0.20, f"Gap {gap:.4f}s too large"

    async def test_first_attempt_success_no_delay(self) -> None:
        start = time.monotonic()

        async def ok() -> str:
            return "fast"

        result = await retry_async(ok, retries=3, base_delay=5.0)
        elapsed = time.monotonic() - start
        assert result == "fast"
        assert elapsed < 1.0, "Should not have waited"

    async def test_factory_called_fresh_each_attempt(self) -> None:
        """operation_factory is invoked per attempt (not a single awaitable reused)."""
        calls: list[int] = []

        def make_op() -> Any:
            async def op() -> str:
                calls.append(len(calls))
                if len(calls) < 3:
                    raise ValueError("retry me")
                return "done"
            return op()

        result = await retry_async(make_op, retries=3, base_delay=0.01, jitter=0.0)
        assert result == "done"
        assert len(calls) == 3

    async def test_base_exception_subclass_not_caught_by_default(self) -> None:
        """KeyboardInterrupt is BaseException, not Exception, so not retried by default."""
        call_count = 0

        async def failing() -> None:
            nonlocal call_count
            call_count += 1
            raise KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            await retry_async(failing, retries=3, base_delay=0.01)

        assert call_count == 1

    async def test_custom_retry_exceptions_tuple(self) -> None:
        call_count = 0

        async def failing() -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("disk")
            if call_count == 2:
                raise ConnectionError("net")
            raise ValueError("done")

        with pytest.raises(ValueError):
            await retry_async(
                failing,
                retries=5,
                retry_exceptions=(OSError, ConnectionError),
                base_delay=0.01,
                jitter=0.0,
            )

        assert call_count == 3  # OSError retried, ConnectionError retried, ValueError not retried


# ---------------------------------------------------------------------------
# bounded_gather
# ---------------------------------------------------------------------------


class TestBoundedGather:
    """Edge cases for bounded_gather."""

    async def test_empty_factories_list(self) -> None:
        results = await bounded_gather([], concurrency_limit=5)
        assert results == []

    async def test_concurrency_one_serializes_execution(self) -> None:
        """With concurrency=1, tasks run sequentially (no overlap)."""
        running = 0
        max_concurrent = 0

        async def tracked(idx: int) -> int:
            nonlocal running, max_concurrent
            running += 1
            if running > max_concurrent:
                max_concurrent = running
            await asyncio.sleep(0.01)
            running -= 1
            return idx

        factories = [lambda i=i: tracked(i) for i in range(5)]
        results = await bounded_gather(factories, concurrency_limit=1)
        assert max_concurrent == 1
        assert results == [0, 1, 2, 3, 4]

    async def test_concurrency_greater_than_tasks(self) -> None:
        """All tasks can run in parallel when concurrency > len(tasks)."""

        async def identity(x: int) -> int:
            return x

        factories = [lambda i=i: identity(i) for i in range(3)]
        results = await bounded_gather(factories, concurrency_limit=100)
        assert results == [0, 1, 2]

    async def test_results_in_original_order(self) -> None:
        """Results match factory order regardless of completion speed."""

        async def delayed(val: int, delay: float) -> int:
            await asyncio.sleep(delay)
            return val

        factories = [
            lambda: delayed(0, 0.04),
            lambda: delayed(1, 0.01),
            lambda: delayed(2, 0.02),
        ]
        results = await bounded_gather(factories, concurrency_limit=10)
        assert results == [0, 1, 2]

    async def test_return_exceptions_true_captures_errors(self) -> None:
        async def ok() -> str:
            return "ok"

        async def fail() -> str:
            raise ValueError("oops")

        factories = [ok, fail, ok]
        results = await bounded_gather(factories, concurrency_limit=10, return_exceptions=True)
        assert results[0] == "ok"
        assert isinstance(results[1], ValueError)
        assert results[2] == "ok"

    async def test_return_exceptions_false_propagates_first_error(self) -> None:
        async def fail() -> str:
            raise ValueError("boom")

        async def slow() -> str:
            await asyncio.sleep(10)
            return "never"

        factories = [fail, slow]
        with pytest.raises(ValueError, match="boom"):
            await bounded_gather(factories, concurrency_limit=10, return_exceptions=False)

    async def test_cancellation_of_inflight_tasks_on_error(self) -> None:
        """When return_exceptions=False, in-flight tasks are cancelled."""
        slow_started = asyncio.Event()
        slow_cancelled = False

        async def slow_op() -> str:
            nonlocal slow_cancelled
            slow_started.set()
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                slow_cancelled = True
                raise
            return "never"

        async def fast_fail() -> str:
            await slow_started.wait()
            raise ValueError("fast fail")

        factories = [slow_op, fast_fail]
        with pytest.raises(ValueError, match="fast fail"):
            await bounded_gather(factories, concurrency_limit=10, return_exceptions=False)

        # Give a tick for cancellation propagation
        await asyncio.sleep(0.05)
        assert slow_cancelled is True

    async def test_single_factory(self) -> None:
        async def single() -> int:
            return 42

        results = await bounded_gather([single], concurrency_limit=1)
        assert results == [42]

    async def test_all_tasks_fail_return_exceptions_true(self) -> None:
        async def fail(i: int) -> None:
            raise ValueError(f"err_{i}")

        factories = [lambda i=i: fail(i) for i in range(3)]
        results = await bounded_gather(factories, concurrency_limit=2, return_exceptions=True)
        assert all(isinstance(r, ValueError) for r in results)
        assert len(results) == 3

    async def test_concurrency_limit_respected_under_load(self) -> None:
        """With concurrency=2 and 6 tasks, no more than 2 run simultaneously."""
        running = 0
        max_concurrent = 0

        async def tracked(idx: int) -> int:
            nonlocal running, max_concurrent
            running += 1
            if running > max_concurrent:
                max_concurrent = running
            await asyncio.sleep(0.02)
            running -= 1
            return idx

        factories = [lambda i=i: tracked(i) for i in range(6)]
        results = await bounded_gather(factories, concurrency_limit=2)
        assert max_concurrent <= 2
        assert results == list(range(6))
