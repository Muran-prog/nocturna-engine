"""Protocol types used by the JSONL subprocess runner."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol


class StreamReaderProtocol(Protocol):
    """Protocol for async byte streams used by subprocess pipes."""

    async def read(self, size: int = -1) -> bytes:
        """Read at most `size` bytes from stream."""


class ProcessProtocol(Protocol):
    """Protocol abstraction for process handles used in tests and runtime."""

    stdout: StreamReaderProtocol | None
    stderr: StreamReaderProtocol | None
    returncode: int | None

    async def wait(self) -> int:
        """Wait for process exit and return code."""

    def kill(self) -> None:
        """Terminate process immediately."""


ProcessFactory = Callable[[list[str]], Awaitable[ProcessProtocol]]

