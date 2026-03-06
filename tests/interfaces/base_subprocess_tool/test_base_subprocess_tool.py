"""Comprehensive edge-case tests for BaseSubprocessTool interface."""

from __future__ import annotations

import asyncio
import sys
from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from nocturna_engine.interfaces.base_subprocess_tool import (
    ANSI_ESCAPE_RE,
    DEFAULT_MAX_OUTPUT_SIZE_BYTES,
    BaseSubprocessTool,
    ProcessResult,
    ToolError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from nocturna_engine.interfaces.base_subprocess_tool.output_limiter import (
    _OutputLimitExceeded,
    _OutputLimiter,
)
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Fake process stubs
# ---------------------------------------------------------------------------


class _FakeStream:
    """Minimal async stream stub."""

    def __init__(self, chunks: list[bytes], *, delay: float = 0.0) -> None:
        self._chunks = list(chunks)
        self._delay = delay

    async def read(self, _size: int) -> bytes:
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _FakeProcess:
    """Minimal subprocess stub for deterministic tests."""

    def __init__(
        self,
        *,
        stdout_chunks: list[bytes],
        stderr_chunks: list[bytes],
        return_code: int,
        wait_delay: float = 0.0,
    ) -> None:
        self.stdout = _FakeStream(stdout_chunks)
        self.stderr = _FakeStream(stderr_chunks)
        self.returncode: int | None = None
        self._return_code = return_code
        self._wait_delay = wait_delay
        self.was_killed = False

    async def wait(self) -> int:
        if self.returncode is None:
            if self._wait_delay > 0:
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


# ---------------------------------------------------------------------------
# Concrete test subclass
# ---------------------------------------------------------------------------


class DummySubprocessTool(BaseSubprocessTool):
    """Concrete test double for BaseSubprocessTool."""

    name = "dummy_subprocess"
    binary_name = sys.executable
    process_timeout_seconds = 10.0
    max_output_size = 10 * 1024 * 1024
    _allowed_flag_prefixes = frozenset({"--version", "--help", "-c"})

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []

    def _build_command(self, request: ScanRequest) -> list[str]:
        return [self.binary_name, "-c", "print('ok')"]


def _monkeypatch_create_subprocess(monkeypatch: pytest.MonkeyPatch, process: _FakeProcess) -> None:
    """Helper to monkeypatch asyncio.create_subprocess_exec."""

    async def fake(*args: object, **kwargs: object) -> _FakeProcess:
        _ = args
        _ = kwargs
        return process

    monkeypatch.setattr(
        "nocturna_engine.interfaces.base_subprocess_tool.asyncio.create_subprocess_exec",
        fake,
    )


# ---------------------------------------------------------------------------
# 1. ClassVar defaults
# ---------------------------------------------------------------------------


class TestClassVarDefaults:
    """Verify ClassVar defaults and overrides."""

    def test_default_max_output_size(self) -> None:
        assert DEFAULT_MAX_OUTPUT_SIZE_BYTES == 50 * 1024 * 1024

    def test_subclass_overrides(self) -> None:
        tool = DummySubprocessTool()
        assert tool.name == "dummy_subprocess"
        assert tool.binary_name == sys.executable
        assert tool.process_timeout_seconds == 10.0

    def test_default_version_args(self) -> None:
        assert DummySubprocessTool.version_args == ("--version",)

    def test_default_help_args(self) -> None:
        assert DummySubprocessTool.help_args == ("--help",)

    def test_default_read_chunk_size(self) -> None:
        assert DummySubprocessTool._read_chunk_size == 8192


# ---------------------------------------------------------------------------
# 2. ProcessResult model
# ---------------------------------------------------------------------------


class TestProcessResultModel:
    """Test ProcessResult Pydantic model."""

    def test_minimal_valid(self) -> None:
        pr = ProcessResult(return_code=0, duration_seconds=1.0, command="echo hi")
        assert pr.stdout == ""
        assert pr.stderr == ""
        assert pr.was_killed is False

    def test_negative_duration_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ProcessResult(return_code=0, duration_seconds=-1.0, command="x")

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ProcessResult(return_code=0, duration_seconds=0.0, command="x", extra="bad")

    def test_all_fields(self) -> None:
        pr = ProcessResult(
            stdout="out",
            stderr="err",
            return_code=1,
            duration_seconds=2.5,
            was_killed=True,
            command="tool --arg",
        )
        assert pr.stdout == "out"
        assert pr.stderr == "err"
        assert pr.return_code == 1
        assert pr.was_killed is True


# ---------------------------------------------------------------------------
# 3. Process execution happy path
# ---------------------------------------------------------------------------


class TestRunProcessHappy:
    """Test successful subprocess execution."""

    async def test_captures_stdout_and_stderr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()
        proc = _FakeProcess(stdout_chunks=[b"hello\n"], stderr_chunks=[b"warn\n"], return_code=0)
        _monkeypatch_create_subprocess(monkeypatch, proc)

        result = await tool._run_process([sys.executable, "--version"], timeout=3.0)
        assert result.return_code == 0
        assert result.stdout == "hello"
        assert result.stderr == "warn"
        assert result.was_killed is False

    async def test_nonzero_return_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()
        proc = _FakeProcess(stdout_chunks=[], stderr_chunks=[b"error\n"], return_code=1)
        _monkeypatch_create_subprocess(monkeypatch, proc)

        result = await tool._run_process([sys.executable, "--version"], timeout=3.0)
        assert result.return_code == 1
        assert result.stderr == "error"

    async def test_multiple_stdout_chunks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()
        proc = _FakeProcess(
            stdout_chunks=[b"chunk1", b"chunk2"],
            stderr_chunks=[],
            return_code=0,
        )
        _monkeypatch_create_subprocess(monkeypatch, proc)

        result = await tool._run_process([sys.executable, "-c", "pass"], timeout=3.0)
        assert result.stdout == "chunk1chunk2"

    async def test_empty_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()
        proc = _FakeProcess(stdout_chunks=[], stderr_chunks=[], return_code=0)
        _monkeypatch_create_subprocess(monkeypatch, proc)

        result = await tool._run_process([sys.executable, "-c", "pass"], timeout=3.0)
        assert result.stdout == ""
        assert result.stderr == ""


# ---------------------------------------------------------------------------
# 4. Timeout handling
# ---------------------------------------------------------------------------


class TestTimeout:
    """Test process timeout kills and raises."""

    async def test_timeout_kills_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()
        proc = _FakeProcess(
            stdout_chunks=[], stderr_chunks=[], return_code=0, wait_delay=5.0,
        )
        _monkeypatch_create_subprocess(monkeypatch, proc)

        with pytest.raises(ToolTimeoutError, match="timed out"):
            await tool._run_process([sys.executable, "-c", "pass"], timeout=0.05)
        assert proc.was_killed is True

    async def test_zero_timeout_raises_tool_error(self) -> None:
        tool = DummySubprocessTool()
        with pytest.raises(ToolError, match="must be > 0"):
            await tool._run_process([sys.executable, "-c", "pass"], timeout=0)

    async def test_negative_timeout_raises_tool_error(self) -> None:
        tool = DummySubprocessTool()
        with pytest.raises(ToolError, match="must be > 0"):
            await tool._run_process([sys.executable, "-c", "pass"], timeout=-1.0)

    def test_resolve_timeout_uses_class_default(self) -> None:
        tool = DummySubprocessTool()
        assert tool._resolve_timeout(None) == tool.process_timeout_seconds

    def test_resolve_timeout_uses_explicit(self) -> None:
        tool = DummySubprocessTool()
        assert tool._resolve_timeout(42.0) == 42.0


# ---------------------------------------------------------------------------
# 5. Output limiting
# ---------------------------------------------------------------------------


class TestOutputLimiting:
    """Test output size limit enforcement."""

    async def test_output_exceeding_limit_kills_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()
        proc = _FakeProcess(
            stdout_chunks=[b"X" * 4096],
            stderr_chunks=[],
            return_code=0,
            wait_delay=5.0,
        )
        _monkeypatch_create_subprocess(monkeypatch, proc)

        with pytest.raises(_OutputLimitExceeded, match="exceeded"):
            await tool._run_process(
                [sys.executable, "-c", "pass"], timeout=3.0, max_output_size=2048
            )
        assert proc.was_killed is True

    def test_output_limiter_allows_within_budget(self) -> None:
        limiter = _OutputLimiter(1000)
        limiter.consume(500)
        limiter.consume(400)  # total 900, ok

    def test_output_limiter_exceeds_budget(self) -> None:
        limiter = _OutputLimiter(100)
        with pytest.raises(_OutputLimitExceeded):
            limiter.consume(101)

    def test_output_limiter_cumulative_exceed(self) -> None:
        limiter = _OutputLimiter(100)
        limiter.consume(60)
        with pytest.raises(_OutputLimitExceeded):
            limiter.consume(50)  # total 110 > 100

    def test_resolve_output_limit_uses_class_default(self) -> None:
        tool = DummySubprocessTool()
        assert tool._resolve_output_limit(None) == tool.max_output_size

    def test_resolve_output_limit_explicit(self) -> None:
        tool = DummySubprocessTool()
        assert tool._resolve_output_limit(512) == 512

    def test_resolve_output_limit_zero_raises(self) -> None:
        tool = DummySubprocessTool()
        with pytest.raises(ToolError, match="must be > 0"):
            tool._resolve_output_limit(0)

    def test_resolve_output_limit_negative_raises(self) -> None:
        tool = DummySubprocessTool()
        with pytest.raises(ToolError, match="must be > 0"):
            tool._resolve_output_limit(-1)


# ---------------------------------------------------------------------------
# 6. Empty command and argument validation
# ---------------------------------------------------------------------------


class TestCommandValidation:
    """Test command validation edge cases."""

    async def test_empty_command_raises(self) -> None:
        tool = DummySubprocessTool()
        with pytest.raises(ToolError, match="cannot be empty"):
            await tool._run_process([], timeout=3.0)

    def test_normalize_arg_empty_string_raises(self) -> None:
        with pytest.raises(ToolError, match="empty argument"):
            DummySubprocessTool._normalize_arg("")

    def test_normalize_arg_null_byte_raises(self) -> None:
        with pytest.raises(ToolError, match="null-byte"):
            DummySubprocessTool._normalize_arg("arg\x00bad")

    def test_normalize_arg_shell_metachar_pipe_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("arg|evil")

    def test_normalize_arg_shell_metachar_semicolon_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("arg;evil")

    def test_normalize_arg_shell_metachar_ampersand_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("arg&evil")

    def test_normalize_arg_shell_metachar_dollar_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("$HOME")

    def test_normalize_arg_shell_metachar_backtick_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("`whoami`")

    def test_normalize_arg_newline_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("arg\nevil")

    def test_normalize_arg_valid_passes(self) -> None:
        result = DummySubprocessTool._normalize_arg("safe-arg")
        assert result == "safe-arg"

    def test_normalize_arg_windows_path_allowed(self) -> None:
        # backslash and quotes are intentionally allowed
        result = DummySubprocessTool._normalize_arg("C:\\Users\\test")
        assert "Users" in result

    def test_normalize_arg_gt_redirect_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("output>file.txt")

    def test_normalize_arg_lt_redirect_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("input<file.txt")

    def test_normalize_arg_hash_raises(self) -> None:
        with pytest.raises(ToolError, match="metacharacter"):
            DummySubprocessTool._normalize_arg("arg#comment")


# ---------------------------------------------------------------------------
# 6b. Argument flag injection validation
# ---------------------------------------------------------------------------


class TestArgumentFlagValidation:
    """Test _validate_argument_flags rejects flag-like injection arguments."""

    def test_flag_rejected_when_no_allowed_prefixes(self) -> None:
        """A flag-like arg is rejected if the tool defines no allowed prefixes."""
        with pytest.raises(ToolError, match="no allowed flags defined"):
            DummySubprocessTool._validate_argument_flags(
                ["nmap", "--output=/etc/cron.d/exploit"], frozenset()
            )

    def test_flag_rejected_when_not_in_allowlist(self) -> None:
        """A flag not matching any allowed prefix is rejected."""
        allowed = frozenset({"--target", "-p"})
        with pytest.raises(ToolError, match="not in allowlist"):
            DummySubprocessTool._validate_argument_flags(
                ["nmap", "--output=/etc/cron.d/exploit", "--target=example.com"], allowed
            )

    def test_flag_passes_when_in_allowlist(self) -> None:
        """A flag matching an allowed prefix passes validation."""
        allowed = frozenset({"--output", "--target"})
        # Should not raise
        DummySubprocessTool._validate_argument_flags(
            ["nmap", "--output=/tmp/report.json", "--target=example.com"], allowed
        )

    def test_non_flag_argument_always_passes(self) -> None:
        """Arguments that don't start with - pass regardless of allowlist."""
        # Empty allowlist, but non-flag args are fine
        DummySubprocessTool._validate_argument_flags(
            ["nmap", "example.com", "192.168.1.0/24", "/path/to/file"], frozenset()
        )

    def test_binary_name_skipped(self) -> None:
        """The first element (binary name) is never validated as a flag."""
        # Binary name starts with - but should be skipped (args[1:] only)
        DummySubprocessTool._validate_argument_flags(
            ["-special-binary", "target.com"], frozenset()
        )

    def test_unix_path_not_treated_as_flag(self) -> None:
        """Unix absolute paths like /usr/bin/tool should not be treated as flags."""
        DummySubprocessTool._validate_argument_flags(
            ["tool", "/usr/local/bin/config", "/etc/hosts"], frozenset()
        )

# ---------------------------------------------------------------------------
# 7. Binary checking
# ---------------------------------------------------------------------------


class TestBinaryCheck:
    """Test _check_binary caching and behavior."""

    async def test_missing_binary_returns_false(self) -> None:
        tool = DummySubprocessTool()
        # Clear cache so test is deterministic
        tool._binary_cache.pop("nonexistent-tool-xyz", None)
        assert await tool._check_binary("nonexistent-tool-xyz") is False

    async def test_empty_binary_name_returns_false(self) -> None:
        tool = DummySubprocessTool()
        assert await tool._check_binary("") is False
        assert await tool._check_binary("  ") is False

    async def test_cache_hit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()
        tool._binary_cache["cached-bin"] = True
        assert await tool._check_binary("cached-bin") is True
        # clean up
        tool._binary_cache.pop("cached-bin", None)

    async def test_python_binary_found(self) -> None:
        tool = DummySubprocessTool()
        tool._binary_cache.pop(sys.executable, None)
        assert await tool._check_binary(sys.executable) is True


# ---------------------------------------------------------------------------
# 8. Health check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    """Test health_check edge cases."""

    async def test_health_check_no_binary_name(self) -> None:
        class NoBinaryTool(DummySubprocessTool):
            binary_name = ""

        tool = NoBinaryTool()
        assert await tool.health_check() is False

    async def test_health_check_missing_binary(self) -> None:
        class MissingTool(DummySubprocessTool):
            binary_name = "definitely-missing-nocturna-binary"

        tool = MissingTool()
        tool._binary_cache.pop("definitely-missing-nocturna-binary", None)
        assert await tool.health_check() is False


# ---------------------------------------------------------------------------
# 9. Output sanitization
# ---------------------------------------------------------------------------


class TestOutputSanitization:
    """Test _sanitize_output and ANSI stripping."""

    def test_ansi_codes_stripped(self) -> None:
        tool = DummySubprocessTool()
        raw = "\x1b[31mred text\x1b[0m"
        assert tool._sanitize_output(raw) == "red text"

    def test_crlf_normalized(self) -> None:
        tool = DummySubprocessTool()
        assert tool._sanitize_output("line1\r\nline2\r") == "line1\nline2"

    def test_stripped_whitespace(self) -> None:
        tool = DummySubprocessTool()
        assert tool._sanitize_output("  hello  ") == "hello"

    def test_ansi_regex_pattern(self) -> None:
        assert ANSI_ESCAPE_RE.sub("", "\x1b[1;32mgreen\x1b[0m") == "green"


# ---------------------------------------------------------------------------
# 10. Command formatting for logs
# ---------------------------------------------------------------------------


class TestCommandFormatting:
    """Test _format_command_for_log sensitive arg masking."""

    def test_normal_args_preserved(self) -> None:
        tool = DummySubprocessTool()
        result = tool._format_command_for_log(["nmap", "-sV", "example.com"])
        assert "nmap" in result
        assert "example.com" in result

    def test_token_flag_masked(self) -> None:
        tool = DummySubprocessTool()
        result = tool._format_command_for_log(["tool", "--token", "secret123"])
        assert "secret123" not in result
        assert "***" in result

    def test_api_key_flag_masked(self) -> None:
        tool = DummySubprocessTool()
        result = tool._format_command_for_log(["tool", "--api-key", "mysecret"])
        assert "mysecret" not in result
        assert "***" in result

    def test_equals_token_masked(self) -> None:
        tool = DummySubprocessTool()
        result = tool._format_command_for_log(["tool", "--token=secret123"])
        assert "secret123" not in result
        assert "***" in result

    def test_auth_header_flag_masked(self) -> None:
        tool = DummySubprocessTool()
        # --header is in the sensitive_flags set
        result = tool._format_command_for_log(["tool", "--header", "Bearer secret"])
        assert "Bearer secret" not in result
        assert "***" in result


# ---------------------------------------------------------------------------
# 11. Error types
# ---------------------------------------------------------------------------


class TestErrorTypes:
    """Test subprocess error hierarchy."""

    def test_tool_error_is_plugin_execution_error(self) -> None:
        from nocturna_engine.exceptions import PluginExecutionError
        assert issubclass(ToolError, PluginExecutionError)

    def test_tool_timeout_is_nocturna_timeout(self) -> None:
        from nocturna_engine.exceptions import NocturnaTimeoutError
        assert issubclass(ToolTimeoutError, NocturnaTimeoutError)

    def test_tool_not_found_is_tool_error(self) -> None:
        assert issubclass(ToolNotFoundError, ToolError)

    async def test_file_not_found_raises_tool_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()

        async def fake_exec(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("no such binary")

        monkeypatch.setattr(
            "nocturna_engine.interfaces.base_subprocess_tool.asyncio.create_subprocess_exec",
            fake_exec,
        )
        with pytest.raises(ToolNotFoundError, match="not available"):
            await tool._run_process(["nonexistent-binary", "--help"], timeout=3.0)

    async def test_os_error_raises_tool_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = DummySubprocessTool()

        async def fake_exec(*args: object, **kwargs: object) -> None:
            raise OSError("permission denied")

        monkeypatch.setattr(
            "nocturna_engine.interfaces.base_subprocess_tool.asyncio.create_subprocess_exec",
            fake_exec,
        )
        with pytest.raises(ToolError, match="Unable to start"):
            await tool._run_process([sys.executable, "-c", "pass"], timeout=3.0)


# ---------------------------------------------------------------------------
# 12. Preflight probes
# ---------------------------------------------------------------------------


class TestPreflightProbes:
    """Test preflight_egress_targets inference."""

    def _make_request(self, **kwargs: Any) -> ScanRequest:
        defaults = dict(targets=[Target(domain="example.com")])
        defaults.update(kwargs)
        return ScanRequest(**defaults)

    def test_domain_target_produces_probe(self) -> None:
        tool = DummySubprocessTool()
        request = self._make_request()
        probes = tool.preflight_egress_targets(request)
        assert any(p.get("host") == "example.com" for p in probes)

    def test_ip_target_produces_probe(self) -> None:
        tool = DummySubprocessTool()
        request = self._make_request(targets=[Target(ip="192.168.1.1")])
        probes = tool.preflight_egress_targets(request)
        assert any(p.get("ip") == "192.168.1.1" for p in probes)

    def test_options_host_produces_probe(self) -> None:
        tool = DummySubprocessTool()
        request = self._make_request(
            options={"dummy_subprocess": {"host": "other.com"}}
        )
        probes = tool.preflight_egress_targets(request)
        assert any(p.get("host") == "other.com" for p in probes)

    def test_options_port_produces_combined_probe(self) -> None:
        tool = DummySubprocessTool()
        request = self._make_request(
            options={"dummy_subprocess": {"port": 443}}
        )
        probes = tool.preflight_egress_targets(request)
        assert any(p.get("port") == 443 for p in probes)

    def test_empty_options_no_extra_probes(self) -> None:
        tool = DummySubprocessTool()
        request = self._make_request(options={})
        probes = tool.preflight_egress_targets(request)
        # Should only have target-based probe
        assert len(probes) >= 1

    def test_deduplication(self) -> None:
        tool = DummySubprocessTool()
        request = self._make_request(
            options={"dummy_subprocess": {"host": "example.com"}}
        )
        probes = tool.preflight_egress_targets(request)
        # example.com from target + example.com from options should not duplicate
        host_probes = [p for p in probes if p.get("host") == "example.com"]
        sources = {p.get("source") for p in host_probes}
        assert len(sources) == len(host_probes)  # each has unique source


# ---------------------------------------------------------------------------
# 13. Preflight normalization helpers
# ---------------------------------------------------------------------------


class TestPreflightNormalization:
    """Test _normalize_host, _normalize_ip, _normalize_port, _normalize_protocol."""

    def test_normalize_host_valid_domain(self) -> None:
        assert DummySubprocessTool._normalize_host("Example.Com") == "example.com"

    def test_normalize_host_trailing_dot_stripped(self) -> None:
        assert DummySubprocessTool._normalize_host("example.com.") == "example.com"

    def test_normalize_host_ip_passthrough(self) -> None:
        assert DummySubprocessTool._normalize_host("192.168.1.1") == "192.168.1.1"

    def test_normalize_host_none(self) -> None:
        assert DummySubprocessTool._normalize_host(None) is None

    def test_normalize_host_empty(self) -> None:
        assert DummySubprocessTool._normalize_host("") is None

    def test_normalize_host_invalid_returns_none(self) -> None:
        assert DummySubprocessTool._normalize_host("not a domain!") is None

    def test_normalize_ip_valid_ipv4(self) -> None:
        assert DummySubprocessTool._normalize_ip("10.0.0.1") == "10.0.0.1"

    def test_normalize_ip_valid_ipv6(self) -> None:
        result = DummySubprocessTool._normalize_ip("::1")
        assert result == "::1"

    def test_normalize_ip_none(self) -> None:
        assert DummySubprocessTool._normalize_ip(None) is None

    def test_normalize_ip_invalid(self) -> None:
        assert DummySubprocessTool._normalize_ip("not-an-ip") is None

    def test_normalize_ip_bracketed_ipv6(self) -> None:
        assert DummySubprocessTool._normalize_ip("[::1]") == "::1"

    def test_normalize_port_valid(self) -> None:
        assert DummySubprocessTool._normalize_port(443) == 443

    def test_normalize_port_string(self) -> None:
        assert DummySubprocessTool._normalize_port("8080") == 8080

    def test_normalize_port_none(self) -> None:
        assert DummySubprocessTool._normalize_port(None) is None

    def test_normalize_port_zero_out_of_range(self) -> None:
        assert DummySubprocessTool._normalize_port(0) is None

    def test_normalize_port_too_high(self) -> None:
        assert DummySubprocessTool._normalize_port(70000) is None

    def test_normalize_port_non_numeric(self) -> None:
        assert DummySubprocessTool._normalize_port("abc") is None

    def test_normalize_protocol_valid(self) -> None:
        assert DummySubprocessTool._normalize_protocol("HTTPS") == "https"

    def test_normalize_protocol_none(self) -> None:
        assert DummySubprocessTool._normalize_protocol(None) is None

    def test_normalize_protocol_empty(self) -> None:
        assert DummySubprocessTool._normalize_protocol("") is None


# ---------------------------------------------------------------------------
# 14. Safe kill
# ---------------------------------------------------------------------------


class TestSafeKill:
    """Test _safe_kill edge cases."""

    def test_safe_kill_already_exited(self) -> None:
        proc = _FakeProcess(stdout_chunks=[], stderr_chunks=[], return_code=0)
        proc.returncode = 0  # already exited
        DummySubprocessTool._safe_kill(proc)  # type: ignore[arg-type]
        assert proc.was_killed is False  # should not attempt kill

    def test_safe_kill_running_process(self) -> None:
        proc = _FakeProcess(stdout_chunks=[], stderr_chunks=[], return_code=0)
        # returncode is None (still running)
        DummySubprocessTool._safe_kill(proc)  # type: ignore[arg-type]
        assert proc.was_killed is True