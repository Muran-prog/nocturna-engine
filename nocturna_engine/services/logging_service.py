"""Structured logging service with sensitive-data masking."""

from __future__ import annotations

import logging
import re
from typing import Any

import structlog
from structlog.stdlib import BoundLogger

SENSITIVE_KEYS = ("token", "secret", "password", "api_key", "authorization", "key")
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,3})?\b")
LONG_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_\-]{20,}\b")
IPV6_PATTERN = re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
URL_SENSITIVE_PARAMS_PATTERN = re.compile(
    r"([?&](?:token|api_key|secret|password|auth|key|credential|session_id)=)[^&\s]+",
    re.IGNORECASE,
)


def _mask_ipv4(value: str) -> str:
    """Mask IPv4 addresses (with optional CIDR suffix) while preserving rough cardinality.

    Args:
        value: Raw string value.

    Returns:
        str: String with masked IPv4 addresses.
    """

    def _replace(match: re.Match[str]) -> str:
        full = match.group(0)
        ip_part, _, cidr_part = full.partition("/")
        octets = ip_part.split(".")
        masked = f"{octets[0]}.{octets[1]}.x.x"
        if cidr_part:
            masked += f"/{cidr_part}"
        return masked

    return IPV4_PATTERN.sub(_replace, value)


def _mask_ipv6(value: str) -> str:
    """Mask IPv6 addresses while preserving the first two groups.

    Args:
        value: Raw string value.

    Returns:
        str: String with masked IPv6 addresses.
    """

    def _replace(match: re.Match[str]) -> str:
        groups = match.group(0).split(":")
        masked_groups = groups[:2] + ["x"] * (len(groups) - 2)
        return ":".join(masked_groups)

    return IPV6_PATTERN.sub(_replace, value)


def _mask_jwt(value: str) -> str:
    """Mask JWT tokens.

    Args:
        value: Raw string value.

    Returns:
        str: String with masked JWT tokens.
    """

    return JWT_PATTERN.sub("***JWT_REDACTED***", value)


def _mask_url_params(value: str) -> str:
    """Mask sensitive URL query parameter values.

    Args:
        value: Raw string value.

    Returns:
        str: String with masked sensitive URL parameter values.
    """

    return URL_SENSITIVE_PARAMS_PATTERN.sub(r"\1***REDACTED***", value)


def _mask_token_like(value: str) -> str:
    """Mask token-like strings.

    Args:
        value: Raw string value.

    Returns:
        str: Masked string.
    """

    return LONG_TOKEN_PATTERN.sub("***REDACTED***", value)


def _mask_value(value: Any, force: bool = False) -> Any:
    """Recursively mask sensitive payload values.

    Args:
        value: Any serializable object.
        force: Whether to always redact scalar text.

    Returns:
        Any: Sanitized value.
    """

    if isinstance(value, dict):
        return {
            key: _mask_value(item, force=force or any(k in key.lower() for k in SENSITIVE_KEYS))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_mask_value(item, force=force) for item in value]
    if isinstance(value, tuple):
        return tuple(_mask_value(item, force=force) for item in value)
    if isinstance(value, str):
        if force:
            return "***REDACTED***"
        return _mask_token_like(_mask_ipv4(_mask_ipv6(_mask_jwt(_mask_url_params(value)))))
    return value


def redact_sensitive_processor(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Structlog processor that redacts sensitive fields.

    Args:
        _: Structlog logger (unused).
        __: Method name (unused).
        event_dict: Event payload.

    Returns:
        dict[str, Any]: Redacted event payload.
    """

    return _mask_value(event_dict)


class LoggingService:
    """Configure and provide structlog loggers."""

    _configured: bool = False

    def __init__(self, level: str = "INFO") -> None:
        """Initialize logging service.

        Args:
            level: Root logging level.
        """

        self._level = level.upper()
        self.configure()

    def configure(self) -> None:
        """Configure structlog and stdlib logging once per process."""

        if LoggingService._configured:
            return

        logging.basicConfig(level=getattr(logging, self._level, logging.INFO), format="%(message)s")
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                redact_sensitive_processor,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        LoggingService._configured = True

    def get_logger(self, name: str = "nocturna_engine") -> BoundLogger:
        """Create a component-specific logger.

        Args:
            name: Logger component name.

        Returns:
            BoundLogger: Structured logger instance.
        """

        return structlog.get_logger(name)

