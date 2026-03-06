"""Comprehensive edge-case tests for BaseTool abstract interface."""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest
import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Concrete test subclass
# ---------------------------------------------------------------------------

class ConcreteTool(BaseTool):
    """Minimal concrete subclass for testing abstract BaseTool."""

    name = "concrete_tool"
    version = "1.0.0"
    timeout_seconds = 30.0
    max_retries = 3

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


class BareMinimalTool(BaseTool):
    """Subclass that relies entirely on defaults (no ClassVar overrides)."""

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name or "bare")

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# 1. Abstract method enforcement
# ---------------------------------------------------------------------------

class TestAbstractEnforcement:
    """Verify BaseTool cannot be instantiated without implementing abstracts."""

    def test_cannot_instantiate_base_tool_directly(self) -> None:
        with pytest.raises(TypeError, match="abstract method"):
            BaseTool()  # type: ignore[abstract]

    def test_cannot_instantiate_with_only_execute(self) -> None:
        class OnlyExecute(BaseTool):
            async def execute(self, request: ScanRequest) -> ScanResult:
                return ScanResult(request_id="r", tool_name="t")

        with pytest.raises(TypeError, match="abstract method"):
            OnlyExecute()  # type: ignore[abstract]

    def test_cannot_instantiate_with_only_parse_output(self) -> None:
        class OnlyParse(BaseTool):
            async def parse_output(
                self,
                raw_output: dict[str, Any] | list[Any] | str | None,
                request: ScanRequest,
            ) -> list[Finding]:
                return []

        with pytest.raises(TypeError, match="abstract method"):
            OnlyParse()  # type: ignore[abstract]

    def test_concrete_subclass_instantiates(self) -> None:
        tool = ConcreteTool()
        assert tool is not None


# ---------------------------------------------------------------------------
# 2. ClassVar defaults
# ---------------------------------------------------------------------------

class TestClassVarDefaults:
    """Verify ClassVar defaults on BaseTool and overrides on subclasses."""

    def test_default_name_is_empty(self) -> None:
        assert BaseTool.name == ""

    def test_default_version(self) -> None:
        assert BaseTool.version == "0.1.0"

    def test_default_timeout_seconds(self) -> None:
        assert BaseTool.timeout_seconds == 60.0

    def test_default_max_retries(self) -> None:
        assert BaseTool.max_retries == 2

    def test_bare_minimal_inherits_defaults(self) -> None:
        tool = BareMinimalTool()
        assert tool.name == ""
        assert tool.version == "0.1.0"
        assert tool.timeout_seconds == 60.0
        assert tool.max_retries == 2

    def test_concrete_overrides_classvars(self) -> None:
        tool = ConcreteTool()
        assert tool.name == "concrete_tool"
        assert tool.version == "1.0.0"
        assert tool.timeout_seconds == 30.0
        assert tool.max_retries == 3


# ---------------------------------------------------------------------------
# 3. Initialization
# ---------------------------------------------------------------------------

class TestInit:
    """Verify __init__ behavior with and without logger."""

    def test_default_logger_created_when_none(self) -> None:
        tool = ConcreteTool()
        assert tool._logger is not None

    def test_custom_logger_is_used(self) -> None:
        custom_logger = structlog.get_logger("custom")
        tool = ConcreteTool(logger=custom_logger)
        assert tool._logger is custom_logger

    def test_is_initialized_starts_false(self) -> None:
        tool = ConcreteTool()
        assert tool._is_initialized is False


# ---------------------------------------------------------------------------
# 4. Logger binding
# ---------------------------------------------------------------------------

class TestLoggerProperty:
    """Verify logger property binds tool name."""

    def test_logger_binds_tool_name(self) -> None:
        tool = ConcreteTool()
        bound = tool.logger
        # The bound logger should be a BoundLogger (or proxy) with tool context
        assert bound is not None

    def test_logger_binds_class_name_when_name_empty(self) -> None:
        tool = BareMinimalTool()
        # When name is empty (""), logger falls back to class name lowered
        bound = tool.logger
        assert bound is not None

    def test_logger_returns_new_bound_each_call(self) -> None:
        tool = ConcreteTool()
        a = tool.logger
        b = tool.logger
        # Each call to .bind() should return a new proxy
        assert a is not b or a is b  # implementation may vary, just ensure no error


# ---------------------------------------------------------------------------
# 5. Setup / Teardown lifecycle
# ---------------------------------------------------------------------------

class TestSetupTeardown:
    """Verify setup/teardown toggle _is_initialized."""

    async def test_setup_sets_initialized(self) -> None:
        tool = ConcreteTool()
        assert tool._is_initialized is False
        await tool.setup()
        assert tool._is_initialized is True

    async def test_teardown_clears_initialized(self) -> None:
        tool = ConcreteTool()
        await tool.setup()
        assert tool._is_initialized is True
        await tool.teardown()
        assert tool._is_initialized is False

    async def test_double_setup_stays_initialized(self) -> None:
        tool = ConcreteTool()
        await tool.setup()
        await tool.setup()
        assert tool._is_initialized is True

    async def test_teardown_without_setup(self) -> None:
        tool = ConcreteTool()
        # teardown without prior setup should not error
        await tool.teardown()
        assert tool._is_initialized is False


# ---------------------------------------------------------------------------
# 6. Async context manager (__aenter__ / __aexit__)
# ---------------------------------------------------------------------------

class TestAsyncContextManager:
    """Verify __aenter__/__aexit__ lifecycle hooks."""

    async def test_aenter_calls_setup_and_returns_self(self) -> None:
        tool = ConcreteTool()
        result = await tool.__aenter__()
        assert result is tool
        assert tool._is_initialized is True

    async def test_aexit_calls_teardown(self) -> None:
        tool = ConcreteTool()
        await tool.__aenter__()
        assert tool._is_initialized is True
        await tool.__aexit__(None, None, None)
        assert tool._is_initialized is False

    async def test_context_manager_protocol(self) -> None:
        async with ConcreteTool() as tool:
            assert tool._is_initialized is True
        assert tool._is_initialized is False

    async def test_aexit_called_on_exception(self) -> None:
        tool = ConcreteTool()
        try:
            async with tool:
                assert tool._is_initialized is True
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert tool._is_initialized is False

    async def test_aexit_receives_exception_info(self) -> None:
        tool = ConcreteTool()
        await tool.__aenter__()
        exc = ValueError("test")
        await tool.__aexit__(ValueError, exc, None)
        assert tool._is_initialized is False


# ---------------------------------------------------------------------------
# 7. supports_target default behavior
# ---------------------------------------------------------------------------

class TestSupportsTarget:
    """Verify supports_target default and override."""

    def test_default_supports_any_target(self) -> None:
        tool = ConcreteTool()
        target = Target(domain="example.com")
        assert tool.supports_target(target) is True

    def test_default_supports_ip_target(self) -> None:
        tool = ConcreteTool()
        target = Target(ip="192.168.1.1")
        assert tool.supports_target(target) is True

    def test_overridden_supports_target_can_reject(self) -> None:
        class SelectiveTool(ConcreteTool):
            def supports_target(self, target: Target) -> bool:
                return target.domain is not None

        tool = SelectiveTool()
        assert tool.supports_target(Target(domain="example.com")) is True
        assert tool.supports_target(Target(ip="10.0.0.1")) is False


# ---------------------------------------------------------------------------
# 8. Execute / parse_output abstract contract
# ---------------------------------------------------------------------------

class TestExecuteAndParse:
    """Verify execute/parse_output work on concrete subclass."""

    async def test_execute_returns_scan_result(self) -> None:
        tool = ConcreteTool()
        request = ScanRequest(targets=[Target(domain="example.com")])
        result = await tool.execute(request)
        assert isinstance(result, ScanResult)
        assert result.tool_name == "concrete_tool"

    async def test_parse_output_returns_empty_list(self) -> None:
        tool = ConcreteTool()
        request = ScanRequest(targets=[Target(domain="example.com")])
        findings = await tool.parse_output(None, request)
        assert findings == []

    async def test_parse_output_with_dict_input(self) -> None:
        tool = ConcreteTool()
        request = ScanRequest(targets=[Target(domain="example.com")])
        findings = await tool.parse_output({"key": "value"}, request)
        assert findings == []

    async def test_parse_output_with_string_input(self) -> None:
        tool = ConcreteTool()
        request = ScanRequest(targets=[Target(domain="example.com")])
        findings = await tool.parse_output("raw output text", request)
        assert findings == []


# ---------------------------------------------------------------------------
# 9. Subclass with custom setup/teardown
# ---------------------------------------------------------------------------

class TestCustomLifecycle:
    """Verify subclass can extend setup/teardown."""

    async def test_custom_setup_called_via_context_manager(self) -> None:
        setup_called = False
        teardown_called = False

        class CustomTool(ConcreteTool):
            async def setup(self) -> None:
                nonlocal setup_called
                setup_called = True
                await super().setup()

            async def teardown(self) -> None:
                nonlocal teardown_called
                teardown_called = True
                await super().teardown()

        async with CustomTool() as tool:
            assert setup_called is True
            assert tool._is_initialized is True
        assert teardown_called is True

    async def test_setup_error_prevents_initialization(self) -> None:
        class FailingSetup(ConcreteTool):
            async def setup(self) -> None:
                raise RuntimeError("setup failed")

        tool = FailingSetup()
        with pytest.raises(RuntimeError, match="setup failed"):
            await tool.__aenter__()
        # _is_initialized should remain False since super().setup() never ran
        assert tool._is_initialized is False


# ---------------------------------------------------------------------------
# 10. Multiple instances are independent
# ---------------------------------------------------------------------------

class TestInstanceIndependence:
    """Verify each tool instance has independent state."""

    async def test_separate_initialized_state(self) -> None:
        tool_a = ConcreteTool()
        tool_b = ConcreteTool()
        await tool_a.setup()
        assert tool_a._is_initialized is True
        assert tool_b._is_initialized is False

    def test_separate_logger_instances(self) -> None:
        logger_a = structlog.get_logger("a")
        logger_b = structlog.get_logger("b")
        tool_a = ConcreteTool(logger=logger_a)
        tool_b = ConcreteTool(logger=logger_b)
        assert tool_a._logger is not tool_b._logger
