"""Reusable async base class for API-backed security tools."""

from __future__ import annotations

import asyncio
import random
from urllib.parse import urlsplit

import aiohttp

from ..errors import (
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
from .tool import BaseApiTool

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
]
