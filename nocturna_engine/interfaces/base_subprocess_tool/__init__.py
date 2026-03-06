"""Reusable subprocess wrapper base class for external binary tools."""

from __future__ import annotations

from . import base as _base
from .base import BaseSubprocessTool
from .constants import ANSI_ESCAPE_RE, DEFAULT_MAX_OUTPUT_SIZE_BYTES
from .errors import ToolError, ToolNotFoundError, ToolTimeoutError
from .models import ProcessResult
from .output_limiter import _OutputLimitExceeded, _OutputLimiter

# Compatibility aliases for existing monkeypatch paths in tests/consumers.
asyncio = _base.asyncio
shutil = _base.shutil

__all__ = [
    "ANSI_ESCAPE_RE",
    "DEFAULT_MAX_OUTPUT_SIZE_BYTES",
    "BaseSubprocessTool",
    "ProcessResult",
    "ToolError",
    "ToolNotFoundError",
    "ToolTimeoutError",
]
