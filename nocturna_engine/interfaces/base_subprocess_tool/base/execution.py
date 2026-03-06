"""Subprocess execution helpers for subprocess-based tools."""

from __future__ import annotations

import asyncio
import shlex
import shutil
from time import perf_counter
from typing import ClassVar

from ..constants import ANSI_ESCAPE_RE
from ..errors import ToolError, ToolNotFoundError, ToolTimeoutError
from ..models import ProcessResult
from ..output_limiter import _OutputLimitExceeded, _OutputLimiter


class _SubprocessExecutionMixin:
    process_timeout_seconds: ClassVar[float]
    max_output_size: ClassVar[int]
    _read_chunk_size: ClassVar[int]
    _binary_cache: ClassVar[dict[str, bool]]
    name: str

    async def _run_process(
        self,
        cmd: list[str],
        timeout: float | None = None,
        max_output_size: int | None = None,
    ) -> ProcessResult:
        """Run subprocess with secure defaults and bounded output collection."""

        if not cmd:
            raise ToolError("Subprocess command cannot be empty.")

        prepared_cmd = [self._normalize_arg(arg) for arg in cmd]
        self._validate_argument_flags(prepared_cmd, getattr(self, '_allowed_flag_prefixes', frozenset()))
        timeout_seconds = self._resolve_timeout(timeout)
        output_limit = self._resolve_output_limit(max_output_size)
        masked_command = self._format_command_for_log(prepared_cmd)
        started = perf_counter()
        was_killed = False

        try:
            process = await asyncio.create_subprocess_exec(
                *prepared_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ToolNotFoundError(
                f"Binary '{prepared_cmd[0]}' is not available in PATH."
            ) from exc
        except OSError as exc:
            raise ToolError(
                f"Unable to start subprocess '{masked_command}': {exc}"
            ) from exc

        if process.stdout is None or process.stderr is None:
            self._safe_kill(process)
            raise ToolError("Subprocess streams are unavailable.")

        limiter = _OutputLimiter(output_limit)
        stdout_task = asyncio.create_task(
            self._read_stream(process=process, stream=process.stdout, limiter=limiter),
            name=f"{self.name or 'tool'}-stdout-reader",
        )
        stderr_task = asyncio.create_task(
            self._read_stream(process=process, stream=process.stderr, limiter=limiter),
            name=f"{self.name or 'tool'}-stderr-reader",
        )

        try:
            return_code, stdout_bytes, stderr_bytes = await asyncio.wait_for(
                self._wait_process(process, stdout_task, stderr_task),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            was_killed = True
            self._safe_kill(process)
            await self._finalize_reader_tasks(stdout_task, stderr_task)
            raise ToolTimeoutError(
                f"Process timed out after {timeout_seconds:.2f}s: {masked_command}"
            ) from exc
        except _OutputLimitExceeded:
            was_killed = True
            self._safe_kill(process)
            await self._finalize_reader_tasks(stdout_task, stderr_task)
            raise
        except Exception as exc:
            self._safe_kill(process)
            await self._finalize_reader_tasks(stdout_task, stderr_task)
            raise ToolError(f"Process execution failed: {masked_command}. {exc}") from exc
        finally:
            if process.returncode is None:
                was_killed = True
                self._safe_kill(process)
                try:
                    await asyncio.wait_for(process.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass

        duration = max(0.0, perf_counter() - started)
        stdout = self._sanitize_output(stdout_bytes.decode("utf-8", errors="replace"))
        stderr = self._sanitize_output(stderr_bytes.decode("utf-8", errors="replace"))
        return ProcessResult(
            stdout=stdout,
            stderr=stderr,
            return_code=int(return_code),
            duration_seconds=duration,
            was_killed=was_killed,
            command=masked_command,
        )

    async def _check_binary(self, binary_name: str) -> bool:
        """Check and cache binary availability in PATH."""

        key = binary_name.strip()
        if not key:
            return False
        if key in self._binary_cache:
            return self._binary_cache[key]
        available = shutil.which(key) is not None
        self._binary_cache[key] = available
        return available

    def _sanitize_output(self, raw: str) -> str:
        """Normalize command output for stable parsing."""

        normalized = raw.encode("utf-8", errors="replace").decode("utf-8")
        normalized = ANSI_ESCAPE_RE.sub("", normalized)
        normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
        return normalized.strip()

    # Characters that enable shell command chaining / substitution.
    # Backslash and quotes are intentionally omitted (Windows paths, tool args).
    _SHELL_INJECTION_CHARS: ClassVar[frozenset[str]] = frozenset(";|&$`()\n\r><#")

    @staticmethod
    def _normalize_arg(value: object) -> str:
        text = str(value)
        if not text:
            raise ToolError("Subprocess command contains an empty argument.")
        if "\x00" in text:
            raise ToolError("Subprocess command contains a null-byte argument.")
        bad = _SubprocessExecutionMixin._SHELL_INJECTION_CHARS.intersection(text)
        if bad:
            sanitized = "".join(ch if ch not in bad else "?" for ch in text)
            raise ToolError(
                f"Subprocess argument contains disallowed shell metacharacter(s) "
                f"{sorted(bad)!r}: {sanitized!r}"
            )
        return text

    @staticmethod
    def _validate_argument_flags(args: list[str], allowed_prefixes: frozenset[str]) -> None:
        """Reject arguments starting with ``-`` unless they match allowed flag prefixes.

        This prevents argument-injection attacks where a malicious target value
        such as ``--output=/etc/cron.d/exploit`` is forwarded to the underlying
        binary (nmap, nuclei, semgrep, etc.) and interpreted as a flag.

        Args:
            args: Full command list (binary + arguments).
            allowed_prefixes: Flag prefixes that the subclass explicitly permits.
                An empty frozenset means *no* flags are allowed.

        Raises:
            ToolError: If a flag-like argument is not covered by *allowed_prefixes*.
        """
        # TODO: Add Windows-style flag detection (/flag) as a future improvement.
        # Checking "/" is risky because it collides with Unix absolute paths.
        for arg in args[1:]:
            if not arg.startswith("-"):
                continue
            if not allowed_prefixes:
                raise ToolError(
                    f"Subprocess argument looks like a flag but no allowed flags defined: {arg!r}. "
                    "Define _allowed_flag_prefixes in your tool subclass."
                )
            if not any(arg.startswith(prefix) for prefix in allowed_prefixes):
                raise ToolError(
                    f"Subprocess argument flag not in allowlist: {arg!r}"
                )

    def _resolve_timeout(self, timeout: float | None) -> float:
        candidate = self.process_timeout_seconds if timeout is None else timeout
        try:
            value = float(candidate)
        except (TypeError, ValueError) as exc:
            raise ToolError(f"Invalid subprocess timeout value: {candidate!r}") from exc
        if value <= 0:
            raise ToolError(f"Subprocess timeout must be > 0, got {candidate!r}")
        return value

    def _resolve_output_limit(self, max_output_size: int | None) -> int:
        candidate = self.max_output_size if max_output_size is None else max_output_size
        try:
            value = int(candidate)
        except (TypeError, ValueError) as exc:
            raise ToolError(f"Invalid max output size: {candidate!r}") from exc
        if value <= 0:
            raise ToolError(f"Max output size must be > 0, got {candidate!r}")
        return value

    def _format_command_for_log(self, cmd: list[str]) -> str:
        masked: list[str] = []
        redact_next = False
        sensitive_flags = {"--token", "--api-key", "--apikey", "--auth", "--header", "-H"}
        for arg in cmd:
            lowered = arg.lower()
            if redact_next:
                masked.append("***")
                redact_next = False
                continue
            if lowered in sensitive_flags:
                masked.append(arg)
                redact_next = True
                continue
            if "=" in arg and any(flag in lowered for flag in ("token=", "api_key=", "apikey=")):
                key = arg.split("=", 1)[0]
                masked.append(f"{key}=***")
                continue
            masked.append(arg)
        return " ".join(shlex.quote(part) for part in masked)

    @staticmethod
    def _safe_kill(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            process.kill()
        except ProcessLookupError:
            return

    async def _wait_process(
        self,
        process: asyncio.subprocess.Process,
        stdout_task: asyncio.Task[bytes],
        stderr_task: asyncio.Task[bytes],
    ) -> tuple[int, bytes, bytes]:
        await process.wait()
        stdout_bytes = await stdout_task
        stderr_bytes = await stderr_task
        return process.returncode if process.returncode is not None else -1, stdout_bytes, stderr_bytes

    async def _read_stream(
        self,
        *,
        process: asyncio.subprocess.Process,
        stream: asyncio.StreamReader,
        limiter: _OutputLimiter,
    ) -> bytes:
        chunks = bytearray()
        while True:
            chunk = await stream.read(self._read_chunk_size)
            if not chunk:
                break
            try:
                limiter.consume(len(chunk))
            except _OutputLimitExceeded:
                self._safe_kill(process)
                raise
            chunks.extend(chunk)
        return bytes(chunks)

    async def _finalize_reader_tasks(
        self,
        stdout_task: asyncio.Task[bytes],
        stderr_task: asyncio.Task[bytes],
    ) -> None:
        for task in (stdout_task, stderr_task):
            if task.done():
                continue
            task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
