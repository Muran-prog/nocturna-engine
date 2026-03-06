"""Pydantic manifest models for Plugin Platform v2."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CapabilityDescriptor(BaseModel):
    """Structured capability description used by planner and introspection."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, frozen=True)

    name: str = Field(min_length=1)
    category: str = Field(default="general", min_length=1)
    tags: tuple[str, ...] = Field(default_factory=tuple)
    coverage_hint: float = Field(default=0.5, ge=0.0, le=1.0)
    cost_hint: float = Field(default=1.0, ge=0.0)


class ExecutionRequirements(BaseModel):
    """Runtime requirements and permission hints for plugin execution."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    subprocess: bool = False
    network: bool = False
    filesystem: bool = False
    required_binaries: tuple[str, ...] = Field(default_factory=tuple)
    max_timeout_seconds: float | None = Field(default=None, gt=0.0)
    max_output_bytes: int | None = Field(default=None, gt=0)


class HealthProfile(BaseModel):
    """Health-check behavior and resilience defaults for plugins."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    startup_check: bool = True
    periodic_check: bool = False
    check_timeout_seconds: float = Field(default=3.0, gt=0.0, le=120.0)
    failure_threshold: int = Field(default=3, ge=1, le=50)
    quarantine_seconds: float = Field(default=300.0, ge=1.0, le=86400.0)


class CompatibilityInfo(BaseModel):
    """Backward compatibility and deprecation metadata."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    legacy_names: tuple[str, ...] = Field(default_factory=tuple)
    deprecated: bool = False
    deprecation_message: str | None = None
    replacement_plugin_id: str | None = None


class PluginManifest(BaseModel):
    """Formal plugin manifest for deterministic discovery and planning."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    version: str = Field(default="0.1.0", min_length=1)
    display_name: str = Field(min_length=1)
    capabilities: tuple[CapabilityDescriptor, ...] = Field(default_factory=tuple)
    supported_targets: tuple[str, ...] = Field(default_factory=tuple)
    supported_phases: tuple[str, ...] = Field(default_factory=tuple)
    option_schema: dict[str, Any] = Field(default_factory=dict)
    execution_requirements: ExecutionRequirements = Field(default_factory=ExecutionRequirements)
    health_profile: HealthProfile = Field(default_factory=HealthProfile)
    compatibility: CompatibilityInfo = Field(default_factory=CompatibilityInfo)

    @field_validator("id")
    @classmethod
    def _normalize_id(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("supported_targets", "supported_phases")
    @classmethod
    def _normalize_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({item.strip().lower() for item in value if item.strip()}))
        return normalized

    def machine_readable(self, include_schema: bool = True) -> dict[str, Any]:
        """Return manifest payload optimized for LLM and API consumption."""

        data = self.model_dump(mode="json")
        if not include_schema:
            data.pop("option_schema", None)
        return data
