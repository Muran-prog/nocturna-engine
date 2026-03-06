"""Process startup behavior for the JSONL subprocess runner."""

from __future__ import annotations

import asyncio
import os

from nocturna_engine.streaming.jsonl_engine.errors import JsonlSubprocessStartError
from nocturna_engine.streaming.jsonl_engine.runner.protocols import ProcessFactory, ProcessProtocol
from nocturna_engine.streaming.jsonl_engine.utils import normalize_command


class RunnerStartMixin:
    """Mixin with subprocess start logic."""

    _process_factory: ProcessFactory | None
    _allowed_binaries: frozenset[str] | None

    async def start(self, command: list[str]) -> ProcessProtocol:
        """Start subprocess execution for given command.

        Args:
            command: Process command arguments.

        Returns:
            ProcessProtocol: Running process handle.

        Raises:
            JsonlSubprocessStartError: If process cannot be started.
        """

        try:
            normalized_command = normalize_command(command)
        except ValueError as exc:
            raise JsonlSubprocessStartError(str(exc)) from exc
        if self._allowed_binaries is not None:
            binary = normalized_command[0]
            binary_name = os.path.basename(binary)
            if binary_name not in self._allowed_binaries and binary not in self._allowed_binaries:
                raise JsonlSubprocessStartError(
                    f"Binary '{binary}' is not in the allowed binaries list. "
                    f"Allowed: {sorted(self._allowed_binaries)}"
                )
        try:
            if self._process_factory is not None:
                process = await self._process_factory(normalized_command)
            else:
                process = await asyncio.create_subprocess_exec(
                    *normalized_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
        except FileNotFoundError as exc:
            raise JsonlSubprocessStartError(
                f"Binary '{normalized_command[0]}' is not available in PATH."
            ) from exc
        except OSError as exc:
            raise JsonlSubprocessStartError(
                f"Unable to start subprocess '{normalized_command[0]}': {exc}"
            ) from exc

        if process.stdout is None or process.stderr is None:
            self.kill(process)
            raise JsonlSubprocessStartError("Subprocess stdout/stderr pipes are unavailable.")
        return process

