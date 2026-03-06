"""Base class composition for subprocess-based tools."""

from __future__ import annotations

import re
from abc import abstractmethod
from typing import ClassVar

from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.scan_request import ScanRequest

from ..constants import DEFAULT_MAX_OUTPUT_SIZE_BYTES
from ..errors import ToolError, ToolTimeoutError
from .execution import _SubprocessExecutionMixin
from .preflight import _PreflightProbeMixin


class BaseSubprocessTool(_PreflightProbeMixin, _SubprocessExecutionMixin, BaseTool):
    """Intermediate base class for tools that invoke external binaries."""

    binary_name: ClassVar[str] = ""
    process_timeout_seconds: ClassVar[float] = 300.0
    max_output_size: ClassVar[int] = DEFAULT_MAX_OUTPUT_SIZE_BYTES
    healthcheck_timeout_seconds: ClassVar[float] = 10.0
    version_args: ClassVar[tuple[str, ...]] = ("--version",)
    help_args: ClassVar[tuple[str, ...]] = ("--help",)
    _read_chunk_size: ClassVar[int] = 8192
    _binary_cache: ClassVar[dict[str, bool]] = {}
    _allowed_flag_prefixes: ClassVar[frozenset[str]] = frozenset()
    _preflight_host_option_keys: ClassVar[frozenset[str]] = frozenset(
        {"target", "targets", "host", "hosts", "domain", "domains", "url", "urls", "endpoint", "endpoints"}
    )
    _preflight_port_option_keys: ClassVar[frozenset[str]] = frozenset({"port", "ports", "target_port", "target_ports"})
    _preflight_protocol_option_keys: ClassVar[frozenset[str]] = frozenset(
        {"protocol", "protocols", "scheme", "schemes"}
    )
    _domain_like_pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    )

    @abstractmethod
    def _build_command(self, request: ScanRequest) -> list[str]:
        """Build subprocess command for tool execution."""

    async def health_check(self) -> bool:
        """Verify binary is available and responds to version/help command."""

        if not self.binary_name:
            return False
        if not await self._check_binary(self.binary_name):
            return False

        for args in (self.version_args, self.help_args):
            if not args:
                continue
            try:
                result = await self._run_process(
                    [self.binary_name, *args],
                    timeout=self.healthcheck_timeout_seconds,
                    max_output_size=min(self.max_output_size, 1 * 1024 * 1024),
                )
            except (ToolError, ToolTimeoutError):
                continue
            if result.return_code == 0:
                return True
        return False
