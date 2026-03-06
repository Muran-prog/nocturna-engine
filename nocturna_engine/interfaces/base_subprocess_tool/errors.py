"""Exception types for subprocess-based tools."""

from __future__ import annotations

from nocturna_engine.exceptions import NocturnaTimeoutError, PluginExecutionError


class ToolError(PluginExecutionError):
    """Raised when subprocess tool operation fails in a recoverable way."""


class ToolTimeoutError(NocturnaTimeoutError):
    """Raised when subprocess tool operation exceeds configured timeout."""


class ToolNotFoundError(ToolError):
    """Raised when required tool binary is unavailable."""
