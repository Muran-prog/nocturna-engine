"""Compatibility adapter for legacy BaseTool plugins under v2 runtime."""

from __future__ import annotations

from typing import Any

from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult

from .contracts import PluginManifest, PluginRuntimeContext


class LegacyToolAdapter:
    """Adapts legacy plugins to the v2 contract without code changes."""

    def __init__(self, *, tool_name: str, tool: Any, manifest: PluginManifest) -> None:
        self.tool_name = tool_name
        self.tool = tool
        self.manifest = manifest

    async def setup(self, context: PluginRuntimeContext) -> None:
        """Run setup and bind runtime context when supported."""

        _ = context
        bind_context = getattr(self.tool, "bind_runtime_context", None)
        if callable(bind_context):
            bind_context(context)
        await self.tool.setup()

    async def teardown(self, context: PluginRuntimeContext) -> None:
        """Run teardown of wrapped legacy tool."""

        _ = context
        await self.tool.teardown()

    async def health_check(self, context: PluginRuntimeContext) -> bool:
        """Proxy optional health_check method with safe fallback."""

        _ = context
        checker = getattr(self.tool, "health_check", None)
        if not callable(checker):
            return True
        result = checker()
        if hasattr(result, "__await__"):
            result = await result
        return bool(result)

    async def execute(self, request: ScanRequest, context: PluginRuntimeContext) -> ScanResult:
        """Execute wrapped tool and keep legacy parse contract."""

        bind_context = getattr(self.tool, "bind_runtime_context", None)
        if callable(bind_context):
            bind_context(context)

        result: ScanResult = await self.tool.execute(request)
        if not result.findings:
            parser = getattr(self.tool, "parse_output", None)
            if callable(parser):
                parsed: list[Finding] = await parser(result.raw_output, request)
                result.findings = parsed

        result.request_id = request.request_id
        result.tool_name = self.tool_name
        result.success = result.success and result.error_message is None
        return result

