"""Pydantic models for subprocess execution results."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ProcessResult(BaseModel):
    """Normalized subprocess execution result."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    stdout: str = ""
    stderr: str = ""
    return_code: int
    duration_seconds: float = Field(ge=0.0)
    was_killed: bool = False
    command: str
