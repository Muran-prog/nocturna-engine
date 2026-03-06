"""Policy and security controls for Plugin Platform v2."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .types import _IPAddress


@dataclass(frozen=True, slots=True)
class EgressEndpoint:
    """Normalized endpoint identity used by egress policy evaluation."""

    host: str | None
    ip: str | None
    port: int | None
    protocol: str | None
    source: str | None = None


@dataclass(frozen=True, slots=True)
class EgressDecision:
    """Decision produced by :class:`EgressPolicyEvaluator`."""

    allowed: bool
    reason: str | None = None
    reason_code: str | None = None
    policy_rule: str | None = None
    matcher: str | None = None
    endpoint: EgressEndpoint | None = None

    def as_context(self) -> dict[str, Any]:
        """Render diagnostics payload suitable for metadata/events."""

        endpoint = self.endpoint
        return {
            "host": endpoint.host if endpoint is not None else None,
            "ip": endpoint.ip if endpoint is not None else None,
            "port": endpoint.port if endpoint is not None else None,
            "protocol": endpoint.protocol if endpoint is not None else None,
            "policy_rule": self.policy_rule,
            "policy_matcher": self.matcher,
            "egress_source": endpoint.source if endpoint is not None else None,
        }


class PluginPolicy(BaseModel):
    """Execution policy controlling plugin permissions and limits."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    allow_subprocess: bool = False
    allow_network: bool = False
    allow_filesystem: bool = False
    max_timeout_seconds: float | None = Field(default=None, gt=0.0)
    max_output_bytes: int | None = Field(default=None, gt=0)
    max_retries: int | None = Field(default=None, ge=0, le=10)
    circuit_breaker_threshold: int = Field(default=3, ge=1, le=50)
    quarantine_seconds: float = Field(default=300.0, ge=1.0, le=86400.0)
    strict_quarantine: bool = False
    allow_cache: bool = True

    egress_allow_hosts: tuple[str, ...] = Field(default_factory=tuple)
    egress_deny_hosts: tuple[str, ...] = Field(default_factory=tuple)
    egress_allow_cidrs: tuple[str, ...] = Field(default_factory=tuple)
    egress_deny_cidrs: tuple[str, ...] = Field(default_factory=tuple)
    egress_allow_ports: tuple[int, ...] = Field(default_factory=tuple)
    egress_deny_ports: tuple[int, ...] = Field(default_factory=tuple)
    egress_allow_protocols: tuple[str, ...] = Field(default_factory=tuple)
    egress_deny_protocols: tuple[str, ...] = Field(default_factory=tuple)
    default_egress_action: Literal["allow", "deny"] = "deny"

    @field_validator(
        "egress_allow_hosts",
        "egress_deny_hosts",
        "egress_allow_cidrs",
        "egress_deny_cidrs",
        mode="before",
    )
    @classmethod
    def _normalize_text_list(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple()
        if isinstance(value, str):
            items: list[Any] = [value]
        elif isinstance(value, list | tuple | set):
            items = list(value)
        else:
            raise ValueError("Value must be a string or list-like of strings.")

        normalized: list[str] = []
        for item in items:
            candidate = str(item).strip().lower()
            if candidate:
                normalized.append(candidate)
        return tuple(normalized)

    @field_validator("egress_allow_cidrs", "egress_deny_cidrs")
    @classmethod
    def _validate_cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for item in value:
            normalized.append(str(ip_network(item, strict=False)))
        return tuple(normalized)

    @field_validator("egress_allow_ports", "egress_deny_ports", mode="before")
    @classmethod
    def _normalize_port_list(cls, value: Any) -> tuple[int, ...]:
        if value is None:
            return tuple()
        if isinstance(value, int):
            items: list[Any] = [value]
        elif isinstance(value, str):
            items = [value]
        elif isinstance(value, list | tuple | set):
            items = list(value)
        else:
            raise ValueError("Ports must be an int or list-like of ints.")

        ports: list[int] = []
        for item in items:
            try:
                port = int(str(item).strip())
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid port value: {item!r}") from exc
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: {port}")
            ports.append(port)
        return tuple(ports)

    @field_validator("egress_allow_protocols", "egress_deny_protocols", mode="before")
    @classmethod
    def _normalize_protocol_list(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple()
        if isinstance(value, str):
            items: list[Any] = [value]
        elif isinstance(value, list | tuple | set):
            items = list(value)
        else:
            raise ValueError("Protocols must be a string or list-like of strings.")

        normalized: list[str] = []
        for item in items:
            candidate = str(item).strip().lower()
            if candidate:
                normalized.append(candidate)
        return tuple(normalized)

    def has_egress_rules(self) -> bool:
        """Return whether policy has active egress constraints."""

        return self.default_egress_action == "deny" or any(
            (
                self.egress_allow_hosts,
                self.egress_deny_hosts,
                self.egress_allow_cidrs,
                self.egress_deny_cidrs,
                self.egress_allow_ports,
                self.egress_deny_ports,
                self.egress_allow_protocols,
                self.egress_deny_protocols,
            )
        )


class PolicyDecision(BaseModel):
    """Policy decision for one plugin execution attempt."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    allowed: bool
    reason: str | None = None
    reason_code: str | None = None
    effective_timeout_seconds: float | None = None
    effective_max_output_bytes: int | None = None
    effective_retries: int | None = None


class PolicyBuildResult(BaseModel):
    """Structured result for policy payload validation and merge."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    policy: PluginPolicy
    valid: bool = True
    reason: str | None = None
    reason_code: str | None = None
    error: str | None = None
