"""Target model used by all scan workflows.

The target model is the canonical input object for scan requests. It supports
IP- and domain-based targets plus optional scope constraints.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

DOMAIN_PATTERN = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"


class Target(BaseModel):
    """Represents a validated scan target.

    Attributes:
        ip: Optional IP address for direct host scans.
        domain: Optional DNS name for domain-based scans.
        scope: Optional allow-list of hosts/networks constrained for this target.
        tags: User-defined labels to route policies or reports.
        metadata: Extra context for plugins and analyzers.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    ip: IPvAnyAddress | None = Field(default=None, description="Primary IP target.")
    domain: str | None = Field(
        default=None,
        description="Primary domain target.",
    )
    scope: list[str] = Field(default_factory=list, description="Scope boundaries.")
    tags: list[str] = Field(default_factory=list, description="Arbitrary target tags.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extra metadata.")

    @model_validator(mode="after")
    def ensure_identifier(self) -> "Target":
        """Require at least one stable target identifier.

        Returns:
            Target: The validated model.

        Raises:
            ValueError: If both `ip` and `domain` are missing.
        """

        if self.ip is None and self.domain is None:
            raise ValueError("Either 'ip' or 'domain' must be provided.")
        return self

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str | None) -> str | None:
        """Normalize domain values for deterministic processing.

        Args:
            value: Raw domain input.

        Returns:
            str | None: Lowercased and trimmed domain value.
        """

        if value is None:
            return None
        normalized = value.strip().lower()
        if len(normalized) > 253:
            raise ValueError("Domain length must be <= 253 characters.")
        if re.fullmatch(DOMAIN_PATTERN, normalized) is None:
            raise ValueError("Domain format is invalid.")
        return normalized

    @field_validator("scope")
    @classmethod
    def validate_scope_entries(cls, value: list[str]) -> list[str]:
        """Validate each scope entry as CIDR, IP, or domain-like text.

        Args:
            value: Scope list provided by a user or orchestrator.

        Returns:
            list[str]: Normalized scope entries.

        Raises:
            ValueError: If any scope value is malformed.
        """

        normalized: list[str] = []
        for entry in value:
            candidate = entry.strip().lower()
            if not candidate:
                raise ValueError("Scope entries must be non-empty strings.")
            if "/" in candidate:
                ip_network(candidate, strict=False)
            else:
                try:
                    ip_address(candidate)
                except ValueError:
                    if len(candidate) > 253 or re.fullmatch(DOMAIN_PATTERN, candidate) is None:
                        raise ValueError(f"Invalid scope entry: {entry!r}") from None
            normalized.append(candidate)
        return normalized
