"""Tests for extensible retry exceptions."""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import aiohttp
import pytest

from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target
from nocturna_engine.utils.async_helpers import (
    TRANSIENT_RETRY_EXCEPTIONS,
    merge_retry_exceptions,
)


# ---------------------------------------------------------------------------
# TRANSIENT_RETRY_EXCEPTIONS defaults
# ---------------------------------------------------------------------------


class TestTransientRetryExceptionsDefaults:
    """Verify base exception types in the default tuple."""

    def test_default_transient_includes_oserror_timeout_connection(self) -> None:
        assert OSError in TRANSIENT_RETRY_EXCEPTIONS
        assert asyncio.TimeoutError in TRANSIENT_RETRY_EXCEPTIONS
        assert ConnectionError in TRANSIENT_RETRY_EXCEPTIONS

    def test_default_transient_includes_aiohttp_client_error(self) -> None:
        """aiohttp is a declared dependency, so ClientError must be present."""
        assert aiohttp.ClientError in TRANSIENT_RETRY_EXCEPTIONS


# ---------------------------------------------------------------------------
# merge_retry_exceptions
# ---------------------------------------------------------------------------


class _CustomTransient(Exception):
    pass


class _AnotherTransient(Exception):
    pass


class TestMergeRetryExceptions:
    """Unit tests for the merge helper."""

    def test_merge_retry_exceptions_adds_custom(self) -> None:
        merged = merge_retry_exceptions((_CustomTransient,))
        assert _CustomTransient in merged
        # Defaults still present
        assert OSError in merged
        assert asyncio.TimeoutError in merged

    def test_merge_retry_exceptions_deduplicates(self) -> None:
        merged = merge_retry_exceptions(
            (OSError, _CustomTransient),
            (_CustomTransient,),
        )
        assert merged.count(OSError) == 1
        assert merged.count(_CustomTransient) == 1

    def test_merge_retry_exceptions_empty_extra(self) -> None:
        merged = merge_retry_exceptions(())
        assert merged == TRANSIENT_RETRY_EXCEPTIONS

    def test_merge_retry_exceptions_no_args(self) -> None:
        merged = merge_retry_exceptions()
        assert merged == TRANSIENT_RETRY_EXCEPTIONS

    def test_merge_retry_exceptions_multiple_groups(self) -> None:
        merged = merge_retry_exceptions(
            (_CustomTransient,),
            (_AnotherTransient,),
        )
        assert _CustomTransient in merged
        assert _AnotherTransient in merged


# ---------------------------------------------------------------------------
# BaseTool.retry_exceptions default
# ---------------------------------------------------------------------------


class TestBaseToolRetryExceptions:
    """Verify BaseTool ships with an empty retry_exceptions tuple."""

    def test_tool_retry_exceptions_default_empty(self) -> None:
        assert BaseTool.retry_exceptions == ()


# ---------------------------------------------------------------------------
# Integration: tool with custom retry_exceptions retries on that exception
# ---------------------------------------------------------------------------


class _RetryKeyErrorTool(BaseTool):
    name: ClassVar[str] = "retry_keyerror_tool"
    version: ClassVar[str] = "1.0.0"
    timeout_seconds: ClassVar[float] = 5.0
    max_retries: ClassVar[int] = 1
    retry_exceptions: ClassVar[tuple[type[BaseException], ...]] = (KeyError,)

    _call_count: int = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        self._call_count += 1
        if self._call_count == 1:
            raise KeyError("transient key miss")
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"ok": True},
        )

    async def parse_output(
        self, raw_output: dict[str, Any] | list[Any] | str | None, request: ScanRequest
    ) -> list[Finding]:
        return [
            Finding(
                title="Test finding",
                description="Integration test finding",
                severity=SeverityLevel.INFO,
                tool=self.name,
                target="example.com",
            )
        ]


def _req(target: str = "example.com") -> ScanRequest:
    return ScanRequest(targets=[Target(domain=target)])


async def test_tool_custom_retry_exceptions_used_in_execution() -> None:
    """Tool with retry_exceptions=(KeyError,) retries and succeeds on second call."""
    pm = PluginManager()
    pm.register_tool_class(_RetryKeyErrorTool)
    await pm.initialize_plugins()

    result = await pm.execute_tool("retry_keyerror_tool", _req())

    assert result.success is True
    assert result.tool_name == "retry_keyerror_tool"
    # Verify the tool was called twice (first raised KeyError, second succeeded)
    tool_instance = pm._instances["retry_keyerror_tool"]
    assert tool_instance._call_count == 2


class _NoRetryKeyErrorTool(BaseTool):
    """Tool that does NOT declare KeyError as retryable — should fail immediately."""

    name: ClassVar[str] = "no_retry_keyerror_tool"
    version: ClassVar[str] = "1.0.0"
    timeout_seconds: ClassVar[float] = 5.0
    max_retries: ClassVar[int] = 1
    # No retry_exceptions override — default is ()

    _call_count: int = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        self._call_count += 1
        if self._call_count == 1:
            raise KeyError("permanent key miss")
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"ok": True},
        )

    async def parse_output(
        self, raw_output: dict[str, Any] | list[Any] | str | None, request: ScanRequest
    ) -> list[Finding]:
        return []


async def test_tool_without_custom_retry_exceptions_does_not_retry_keyerror() -> None:
    """Tool without custom retry_exceptions fails on KeyError without retrying."""
    pm = PluginManager()
    pm.register_tool_class(_NoRetryKeyErrorTool)
    await pm.initialize_plugins()

    result = await pm.execute_tool("no_retry_keyerror_tool", _req())

    assert result.success is False
    tool_instance = pm._instances["no_retry_keyerror_tool"]
    assert tool_instance._call_count == 1  # No retry happened
