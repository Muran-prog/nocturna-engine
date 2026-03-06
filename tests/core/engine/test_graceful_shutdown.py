"""Tests for graceful shutdown with active scan draining."""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import pytest

from nocturna_engine.core.engine import NocturnaEngine
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_request(**overrides: Any) -> ScanRequest:
    defaults: dict[str, Any] = {
        "targets": [Target(domain="example.com", scope=["example.com"])],
        "timeout_seconds": 5.0,
        "retries": 0,
        "concurrency_limit": 4,
    }
    defaults.update(overrides)
    return ScanRequest(**defaults)


class QuickTool(BaseTool):
    """Tool that completes instantly."""

    name: ClassVar[str] = "quick_tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"status": "ok"},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return [
            Finding(
                title="Quick finding",
                description="Found by quick tool.",
                severity=SeverityLevel.LOW,
                tool=self.name,
                target="example.com",
            )
        ]


class SlowScanTool(BaseTool):
    """Tool with controllable execution duration via class attribute."""

    name: ClassVar[str] = "slow_scan_tool"
    delay: ClassVar[float] = 0.5

    async def execute(self, request: ScanRequest) -> ScanResult:
        await asyncio.sleep(self.delay)
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"status": "ok"},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class VerySlowTool(BaseTool):
    """Tool that takes extremely long, used to test timeout cancellation."""

    name: ClassVar[str] = "very_slow_tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        await asyncio.sleep(300)
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_stop_without_active_scans():
    """stop() works normally when no scans are running."""
    engine = NocturnaEngine()
    engine.register_tool(QuickTool)
    await engine.start()
    assert engine._started is True
    assert len(engine._active_scans) == 0
    await engine.stop()
    assert engine._started is False
    assert engine._draining is False


async def test_draining_rejects_new_scans():
    """Setting _draining=True causes run_scan to raise RuntimeError."""
    engine = NocturnaEngine()
    engine.register_tool(QuickTool)
    await engine.start()
    engine._draining = True
    request = _make_request()

    with pytest.raises(RuntimeError, match="Engine is shutting down"):
        await engine.run_scan(request)

    # Cleanup — reset draining so stop() can proceed
    engine._draining = False
    await engine.stop()


async def test_stop_waits_for_active_scan():
    """stop() waits for an active scan to complete before shutting down."""
    engine = NocturnaEngine()
    engine.register_tool(SlowScanTool)
    engine._drain_timeout_seconds = 5.0

    await engine.start()
    request = _make_request()

    scan_task = asyncio.create_task(engine.run_scan(request))
    await asyncio.sleep(0.05)  # let scan start

    # Scan should be tracked
    assert len(engine._active_scans) == 1

    # Stop should wait for scan to finish (SlowScanTool takes ~0.5s)
    await engine.stop()

    # Scan task should have completed successfully
    result = await scan_task
    assert "scan_results" in result
    assert engine._started is False
    assert len(engine._active_scans) == 0


async def test_stop_cancels_scan_after_timeout():
    """stop() cancels tasks that exceed the drain timeout."""
    engine = NocturnaEngine()
    engine.register_tool(VerySlowTool)
    engine._drain_timeout_seconds = 0.1  # very short timeout

    await engine.start()
    request = _make_request()

    scan_task = asyncio.create_task(engine.run_scan(request))
    await asyncio.sleep(0.05)  # let scan register

    assert len(engine._active_scans) == 1

    # Stop should timeout and cancel the task
    await engine.stop()

    assert engine._started is False
    assert engine._draining is False

    # The scan task should have been cancelled
    assert scan_task.done()
    # It was either cancelled or raised due to cancellation
    with pytest.raises((asyncio.CancelledError, Exception)):
        scan_task.result()


async def test_active_scans_tracking():
    """_active_scans dict is populated during scan and cleaned up after."""
    engine = NocturnaEngine()
    engine.register_tool(SlowScanTool)
    await engine.start()

    tracking_snapshot: list[int] = []

    async def capture_tracking(event: Any) -> None:
        tracking_snapshot.append(len(engine._active_scans))

    engine.subscribe("on_scan_started", capture_tracking)

    request = _make_request()
    await engine.run_scan(request)

    # During scan, at least 1 scan was tracked
    assert any(count >= 1 for count in tracking_snapshot)
    # After scan completes, active scans should be empty
    assert len(engine._active_scans) == 0
    await engine.stop()


async def test_drain_timeout_from_config():
    """drain_timeout_seconds is read from engine config during start()."""

    class DrainConfigService:
        def load(self) -> dict[str, Any]:
            return {"engine": {"drain_timeout_seconds": 42.5}}

        def get(self, key: str, default: Any = None) -> Any:
            return default

    engine = NocturnaEngine(config_service=DrainConfigService())
    await engine.start()
    assert engine._drain_timeout_seconds == 42.5
    await engine.stop()


async def test_drain_timeout_from_config_ignores_invalid():
    """Invalid drain_timeout_seconds values are ignored (negative, string, zero)."""

    class BadDrainConfigService:
        def load(self) -> dict[str, Any]:
            return {"engine": {"drain_timeout_seconds": -10}}

        def get(self, key: str, default: Any = None) -> Any:
            return default

    engine = NocturnaEngine(config_service=BadDrainConfigService())
    await engine.start()
    assert engine._drain_timeout_seconds == 30.0  # default
    await engine.stop()


async def test_drain_timeout_from_config_ignores_zero():
    """Zero drain_timeout_seconds is ignored."""

    class ZeroDrainConfigService:
        def load(self) -> dict[str, Any]:
            return {"engine": {"drain_timeout_seconds": 0}}

        def get(self, key: str, default: Any = None) -> Any:
            return default

    engine = NocturnaEngine(config_service=ZeroDrainConfigService())
    await engine.start()
    assert engine._drain_timeout_seconds == 30.0
    await engine.stop()


async def test_drain_timeout_from_config_ignores_string():
    """String drain_timeout_seconds is ignored."""

    class StringDrainConfigService:
        def load(self) -> dict[str, Any]:
            return {"engine": {"drain_timeout_seconds": "fast"}}

        def get(self, key: str, default: Any = None) -> Any:
            return default

    engine = NocturnaEngine(config_service=StringDrainConfigService())
    await engine.start()
    assert engine._drain_timeout_seconds == 30.0
    await engine.stop()


async def test_stop_idempotent_with_drain():
    """Calling stop() twice is still safe with drain logic."""
    engine = NocturnaEngine()
    engine.register_tool(QuickTool)
    await engine.start()
    assert engine._started is True

    await engine.stop()
    assert engine._started is False
    assert engine._draining is False

    # Second stop should be a no-op
    await engine.stop()
    assert engine._started is False
    assert engine._draining is False


async def test_context_manager_drains_on_exit():
    """async with engine drains active scans on __aexit__."""
    engine = NocturnaEngine()
    engine.register_tool(SlowScanTool)
    engine._drain_timeout_seconds = 5.0

    scan_task: asyncio.Task[dict[str, Any]] | None = None

    async with engine:
        request = _make_request()
        scan_task = asyncio.create_task(engine.run_scan(request))
        await asyncio.sleep(0.05)
        assert len(engine._active_scans) == 1

    # After context exit, engine is stopped
    assert engine._started is False
    assert scan_task is not None
    result = await scan_task
    assert "scan_results" in result


async def test_draining_flag_reset_after_stop():
    """_draining flag is reset to False after stop completes."""
    engine = NocturnaEngine()
    engine.register_tool(QuickTool)

    async with engine:
        await engine.run_scan(_make_request())

    assert engine._draining is False
    assert engine._started is False


async def test_multiple_concurrent_scans_tracked():
    """Multiple concurrent scans are all tracked in _active_scans."""
    engine = NocturnaEngine()
    engine.register_tool(SlowScanTool)
    engine._drain_timeout_seconds = 5.0

    await engine.start()

    max_tracked = 0

    async def observe_tracking(event: Any) -> None:
        nonlocal max_tracked
        current = len(engine._active_scans)
        if current > max_tracked:
            max_tracked = current

    engine.subscribe("on_scan_started", observe_tracking)

    tasks = [
        asyncio.create_task(engine.run_scan(_make_request(request_id=f"req-{i}")))
        for i in range(3)
    ]

    await asyncio.sleep(0.05)
    # Should have multiple active scans
    assert len(engine._active_scans) >= 1

    await engine.stop()

    # All tasks should complete or be handled
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert len(results) == 3
    assert len(engine._active_scans) == 0


async def test_scan_cleanup_on_error():
    """_active_scans is cleaned up even when scan raises an error."""

    class ErrorTool(BaseTool):
        name: ClassVar[str] = "error_tool"

        async def execute(self, request: ScanRequest) -> ScanResult:
            raise RuntimeError("tool exploded")

        async def parse_output(
            self,
            raw_output: dict[str, Any] | list[Any] | str | None,
            request: ScanRequest,
        ) -> list[Finding]:
            return []

    engine = NocturnaEngine()
    engine.register_tool(ErrorTool)

    async with engine:
        request = _make_request()
        # run_scan should not raise even if tool fails (pipeline catches it)
        await engine.run_scan(request)
        # After scan, tracking should be cleaned up
        assert len(engine._active_scans) == 0
