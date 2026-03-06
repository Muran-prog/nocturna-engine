"""Plugin protocol and base class for Plugin Platform v2."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel

from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult

from .context import PluginRuntimeContext
from .manifest import PluginManifest


@runtime_checkable
class ToolV2Protocol(Protocol):
    """Formal v2 plugin protocol."""

    manifest: PluginManifest

    async def setup(self) -> None:
        """Initialize plugin resources."""

    async def teardown(self) -> None:
        """Release plugin resources."""

    async def execute_v2(self, request: ScanRequest, context: PluginRuntimeContext) -> ScanResult:
        """Execute plugin using v2 runtime context."""

    async def health_check(self) -> bool:
        """Fast health check used in preflight orchestration."""


class BaseToolV2(BaseTool):
    """Base class for new AI-first plugins while preserving legacy contracts."""

    manifest: ClassVar[PluginManifest | None] = None
    options_model: ClassVar[type[BaseModel] | None] = None

    def __init__(self, logger: Any | None = None) -> None:
        super().__init__(logger=logger)
        self._runtime_context: PluginRuntimeContext | None = None

    def bind_runtime_context(self, context: PluginRuntimeContext) -> None:
        """Attach runtime context before execution."""

        self._runtime_context = context

    @property
    def runtime_context(self) -> PluginRuntimeContext | None:
        """Return currently bound runtime context."""

        return self._runtime_context

    async def execute(self, request: ScanRequest) -> ScanResult:
        """Bridge legacy execute contract to the v2 execution method."""

        context = self._runtime_context
        if context is None:
            raise RuntimeError(
                "PluginRuntimeContext must be bound before execution. "
                "Use bind_runtime_context() or execute_v2() directly."
            )
        return await self.execute_v2(request, context)

    async def teardown(self) -> None:
        """Release plugin resources including temp storage."""
        if self._runtime_context is not None:
            storage = self._runtime_context.storage
            if hasattr(storage, "cleanup"):
                storage.cleanup()
        await super().teardown()

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        """V2 plugins return normalized findings directly from `execute_v2`."""

        _ = raw_output
        _ = request
        return []

    @abstractmethod
    async def execute_v2(self, request: ScanRequest, context: PluginRuntimeContext) -> ScanResult:
        """Execute plugin using v2 runtime contracts."""
