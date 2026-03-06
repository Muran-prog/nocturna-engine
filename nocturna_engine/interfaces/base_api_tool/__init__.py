"""Reusable async base class for API-backed security tools."""

from __future__ import annotations

from . import base as _base
from .base import BaseApiTool
from .models import ApiConfig, ApiResponse
from .errors import (
    ApiError,
    ApiEgressPolicyError,
    ApiOriginError,
    ApiTimeoutError,
    AuthenticationError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
)

# Compatibility aliases for existing monkeypatch paths in tests/consumers.
aiohttp = _base.aiohttp
asyncio = _base.asyncio
random = _base.random
urlsplit = _base.urlsplit

__all__ = [
    "ApiError",
    "ApiEgressPolicyError",
    "ApiOriginError",
    "ApiTimeoutError",
    "AuthenticationError",
    "BaseApiTool",
    "NetworkError",
    "NotFoundError",
    "PermissionError",
    "RateLimitError",
    "ServerError",
    "ApiConfig",
    "ApiResponse",
]
