"""Exceptions for API-backed security tools."""

from __future__ import annotations

from nocturna_engine.exceptions import NocturnaTimeoutError, PluginExecutionError


class ApiError(PluginExecutionError):
    """Base exception for API request failures."""


class ApiTimeoutError(NocturnaTimeoutError):
    """Raised when API polling exceeds the configured timeout."""


class AuthenticationError(ApiError):
    """Raised when API credentials are invalid."""


class PermissionError(ApiError):
    """Raised when API credentials lack required permissions."""


class NotFoundError(ApiError):
    """Raised when requested API resource does not exist."""


class RateLimitError(ApiError):
    """Raised when API rate limits reject the request."""

    def __init__(self, message: str, *, retry_after_seconds: float | None = None) -> None:
        """Initialize rate-limit exception.

        Args:
            message: Human-readable error message.
            retry_after_seconds: Optional retry-after duration from server headers.
        """

        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class ServerError(ApiError):
    """Raised when API server returns 5xx responses."""


class NetworkError(ApiError):
    """Raised when API request fails at transport layer."""


class ApiOriginError(ApiError):
    """Raised when request URL origin is not allowed by API base URL policy."""


class ApiEgressPolicyError(ApiError):
    """Raised when runtime egress policy denies API endpoint access."""


__all__ = [
    "ApiError",
    "ApiEgressPolicyError",
    "ApiOriginError",
    "ApiTimeoutError",
    "AuthenticationError",
    "NetworkError",
    "NotFoundError",
    "PermissionError",
    "RateLimitError",
    "ServerError",
]
