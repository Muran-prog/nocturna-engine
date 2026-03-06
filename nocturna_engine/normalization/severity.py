"""Cross-tool severity normalization with configurable mapping tables."""

from __future__ import annotations

import math
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field, model_validator

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.errors import SeverityMappingError

logger = structlog.get_logger("normalization.severity")

# Default mapping from common tool-native severity strings to SeverityLevel.
# Keys are lowercase, stripped. The mapping is applied after normalization.
_DEFAULT_SEVERITY_TABLE: dict[str, SeverityLevel] = {
    # Universal / common across tools
    "critical": SeverityLevel.CRITICAL,
    "crit": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "med": SeverityLevel.MEDIUM,
    "moderate": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
    "information": SeverityLevel.INFO,
    "none": SeverityLevel.INFO,
    "unknown": SeverityLevel.INFO,
    # SARIF levels
    "error": SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "note": SeverityLevel.LOW,
    # CVSS-style numeric severity names
    "urgent": SeverityLevel.CRITICAL,
    "important": SeverityLevel.HIGH,
    "minor": SeverityLevel.LOW,
    "trivial": SeverityLevel.INFO,
}


class SeverityMap(BaseModel):
    """Configurable severity mapping with per-tool override support.

    Attributes:
        default_table: Base mapping from string labels to SeverityLevel.
        tool_overrides: Per-tool mapping overrides (tool_name → label → SeverityLevel).
        fallback_severity: Severity used when no mapping matches and strict is False.
        strict: If True, unmapped severity values raise SeverityMappingError.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    default_table: dict[str, SeverityLevel] = Field(
        default_factory=lambda: dict(_DEFAULT_SEVERITY_TABLE),
    )
    tool_overrides: dict[str, dict[str, SeverityLevel]] = Field(
        default_factory=dict,
    )
    fallback_severity: SeverityLevel = Field(default=SeverityLevel.INFO)
    strict: bool = Field(default=False)

    @model_validator(mode="after")
    def _normalize_table_keys(self) -> "SeverityMap":
        """Ensure all dict keys in default_table and tool_overrides are normalised."""
        object.__setattr__(
            self,
            "default_table",
            {k.strip().lower(): v for k, v in self.default_table.items()},
        )
        normalised_overrides: dict[str, dict[str, SeverityLevel]] = {}
        for tool_key, mapping in self.tool_overrides.items():
            normalised_overrides[tool_key.strip().lower()] = {
                k.strip().lower(): v for k, v in mapping.items()
            }
        object.__setattr__(self, "tool_overrides", normalised_overrides)
        return self

    def resolve(
        self,
        raw_severity: str,
        *,
        tool_name: str | None = None,
    ) -> SeverityLevel:
        """Map a tool-native severity string to a normalized SeverityLevel.

        Args:
            raw_severity: Raw severity value from tool output.
            tool_name: Optional tool name for per-tool override lookup.

        Returns:
            SeverityLevel: Normalized severity.

        Raises:
            SeverityMappingError: If strict mode is enabled and no mapping found.
        """
        normalized_key = str(raw_severity).strip().lower()
        if not normalized_key:
            if self.strict:
                raise SeverityMappingError(
                    f"Empty severity value from tool={tool_name!r}.",
                )
            return self.fallback_severity

        # Check tool-specific overrides first.
        if tool_name is not None:
            tool_key = tool_name.strip().lower()
            tool_table = self.tool_overrides.get(tool_key)
            if tool_table is not None:
                mapped = tool_table.get(normalized_key)
                if mapped is not None:
                    return mapped

        # Check default table.
        mapped = self.default_table.get(normalized_key)
        if mapped is not None:
            return mapped

        # Try direct SeverityLevel value match (only in non-strict mode).
        if not self.strict:
            try:
                return SeverityLevel(normalized_key)
            except ValueError:
                pass

        if self.strict:
            raise SeverityMappingError(
                f"Unmapped severity {raw_severity!r} from tool={tool_name!r}.",
                context={"raw_severity": raw_severity, "tool_name": tool_name},
            )

        logger.warning(
            "severity_mapping_fallback",
            raw_severity=raw_severity,
            tool_name=tool_name,
            fallback=self.fallback_severity.value,
        )
        return self.fallback_severity

    def resolve_cvss(self, score: float) -> SeverityLevel:
        """Map a CVSS score (0.0-10.0) to SeverityLevel.

        Args:
            score: CVSS v3 base score.

        Returns:
            SeverityLevel: Mapped severity level.

        Raises:
            ValueError: If score is outside [0.0, 10.0] or is NaN/Inf.
        """
        if math.isnan(score) or math.isinf(score):
            raise ValueError(f"CVSS score must be a finite number, got {score!r}.")
        if not (0.0 <= score <= 10.0):
            raise ValueError(
                f"CVSS score must be between 0.0 and 10.0, got {score!r}."
            )
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        if score >= 7.0:
            return SeverityLevel.HIGH
        if score >= 4.0:
            return SeverityLevel.MEDIUM
        if score >= 0.1:
            return SeverityLevel.LOW
        return SeverityLevel.INFO


def build_severity_map(
    *,
    overrides: dict[str, dict[str, SeverityLevel]] | None = None,
    extra_mappings: dict[str, SeverityLevel] | None = None,
    fallback: SeverityLevel = SeverityLevel.INFO,
    strict: bool = False,
) -> SeverityMap:
    """Build a SeverityMap with optional customizations.

    Args:
        overrides: Per-tool severity overrides.
        extra_mappings: Additional default table entries.
        fallback: Fallback severity for unmapped values.
        strict: Whether to raise on unmapped values.

    Returns:
        SeverityMap: Configured severity mapper.
    """
    table = dict(_DEFAULT_SEVERITY_TABLE)
    if extra_mappings:
        table.update(extra_mappings)
    return SeverityMap(
        default_table=table,
        tool_overrides=overrides or {},
        fallback_severity=fallback,
        strict=strict,
    )


def merge_severities(severities: list[SeverityLevel]) -> SeverityLevel:
    """Return the highest severity from a list (used in dedup merging).

    Args:
        severities: List of severity levels to compare.

    Returns:
        SeverityLevel: Highest (most critical) severity in the list.
    """
    if not severities:
        return SeverityLevel.INFO
    _SEVERITY_ORDER: dict[SeverityLevel, int] = {
        SeverityLevel.CRITICAL: 4,
        SeverityLevel.HIGH: 3,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 1,
        SeverityLevel.INFO: 0,
    }
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s, 0))
