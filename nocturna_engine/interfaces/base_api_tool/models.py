"""Pydantic models for API tool configuration and response contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiConfig(BaseModel):
    """Configuration for API-backed tool connections."""

    model_config = ConfigDict(frozen=True)

    base_url: str
    api_key: str
    verify_ssl: bool = True
    max_retries: int = 3
    rate_limit_per_second: int = 10
    pool_size: int = 10
    timeout_total: float = 60.0
    timeout_connect: float = 10.0
    timeout_read: float = 30.0
    auth_header_mode: Literal["bearer", "x-api-key", "both"] = "bearer"


class ApiResponse(BaseModel):
    """Normalized response payload returned by API requests."""

    model_config = ConfigDict(frozen=True)

    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    duration_ms: float = 0.0
    request_method: str = ""
    request_path: str = ""
