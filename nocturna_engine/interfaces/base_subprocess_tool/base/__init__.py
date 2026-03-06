"""Core implementation for subprocess-based tools."""

from __future__ import annotations

from . import execution as _execution
from .tool import BaseSubprocessTool

# Compatibility aliases for existing monkeypatch paths in tests/consumers.
asyncio = _execution.asyncio
shutil = _execution.shutil

__all__ = ["BaseSubprocessTool", "asyncio", "shutil"]
