"""Async execution helpers for retries, timeouts, and concurrency limits."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable, Sequence
from typing import TypeVar

from nocturna_engine.exceptions import NocturnaTimeoutError

T = TypeVar("T")

_OPTIONAL_RETRY_EXCEPTIONS: list[type[BaseException]] = []

try:
    import aiohttp

    _OPTIONAL_RETRY_EXCEPTIONS.append(aiohttp.ClientError)
except ImportError:
    pass

TRANSIENT_RETRY_EXCEPTIONS: tuple[type[BaseException], ...] = (
    OSError,
    asyncio.TimeoutError,
    ConnectionError,
    *_OPTIONAL_RETRY_EXCEPTIONS,
)


async def with_timeout(operation: Awaitable[T], timeout_seconds: float, operation_name: str) -> T:
    """Await operation with timeout protection.

    Args:
        operation: Awaitable operation.
        timeout_seconds: Timeout in seconds.
        operation_name: Logical operation name for error context.

    Returns:
        T: Operation result.

    Raises:
        NocturnaTimeoutError: If timeout is exceeded.
    """

    try:
        return await asyncio.wait_for(operation, timeout=timeout_seconds)
    except TimeoutError as exc:
        raise NocturnaTimeoutError(
            f"Operation '{operation_name}' timed out after {timeout_seconds:.2f}s"
        ) from exc


async def retry_async(
    operation_factory: Callable[[], Awaitable[T]],
    retries: int = 2,
    base_delay: float = 0.25,
    max_delay: float = 5.0,
    jitter: float = 0.2,
    retry_exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> T:
    """Retry async operation with exponential backoff.

    Args:
        operation_factory: Factory that creates a fresh awaitable per attempt.
        retries: Number of retry attempts after the initial failure.
        base_delay: Initial backoff delay in seconds.
        max_delay: Maximum backoff delay in seconds.
        jitter: Random jitter added to each delay.
        retry_exceptions: Exception types eligible for retry.

    Returns:
        T: Operation result.
    """

    attempt = 0
    while True:
        try:
            return await operation_factory()
        except retry_exceptions:
            if attempt >= retries:
                raise
            delay = min(max_delay, base_delay * (2**attempt))
            delay += random.uniform(0.0, jitter)
            await asyncio.sleep(delay)
            attempt += 1


async def bounded_gather(
    operation_factories: Sequence[Callable[[], Awaitable[T]]],
    concurrency_limit: int,
    return_exceptions: bool = False,
) -> list[T | BaseException]:
    """Run many async operations with a semaphore limit.

    Args:
        operation_factories: Factories returning awaitable operations.
        concurrency_limit: Maximum number of in-flight operations.
        return_exceptions: Whether gather should return exceptions.

    Returns:
        list[T | BaseException]: Ordered list of results.
    """

    semaphore = asyncio.Semaphore(concurrency_limit)

    async def _run(factory: Callable[[], Awaitable[T]]) -> T:
        async with semaphore:
            return await factory()

    tasks = [asyncio.create_task(_run(factory)) for factory in operation_factories]
    try:
        return await asyncio.gather(*tasks, return_exceptions=return_exceptions)
    except BaseException:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def merge_retry_exceptions(
    *extra: tuple[type[BaseException], ...],
) -> tuple[type[BaseException], ...]:
    """Merge default transient retry exceptions with extra exception types."""
    combined: list[type[BaseException]] = list(TRANSIENT_RETRY_EXCEPTIONS)
    for group in extra:
        for exc_type in group:
            if exc_type not in combined:
                combined.append(exc_type)
    return tuple(combined)
