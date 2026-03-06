"""Unified finding model produced by analyzers and tools."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SeverityLevel(str, Enum):
    """Standardized severity taxonomy across all integrations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _normalize_token(value: Any, *, lowercase: bool = True) -> str:
    normalized = " ".join(str(value).strip().split())
    if lowercase:
        return normalized.lower()
    return normalized


def _collect_normalized_keys(value: Any, *, prefix: str = "") -> set[str]:
    keys: set[str] = set()

    if isinstance(value, Mapping):
        for key, item in value.items():
            key_token = _normalize_token(key)
            if not key_token:
                continue
            path = f"{prefix}.{key_token}" if prefix else key_token
            keys.add(path)
            keys.update(_collect_normalized_keys(item, prefix=path))
        return keys

    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            keys.update(_collect_normalized_keys(item, prefix=prefix))
        return keys

    return keys


def _normalize_evidence_value(value: Any) -> bool | int | float | str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value == float("inf"):
            return "inf"
        if value == float("-inf"):
            return "-inf"
        if value != value:
            return "nan"
        return round(value, 6)
    normalized = _normalize_token(value, lowercase=True)
    if not normalized:
        return None
    if len(normalized) > 256:
        return normalized[:256]
    return normalized


def _collect_significant_evidence_values(value: Any, *, prefix: str = "") -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        collected: list[dict[str, Any]] = []
        for key in sorted(value.keys(), key=lambda item: _normalize_token(item)):
            key_token = _normalize_token(key)
            if not key_token:
                continue
            path = f"{prefix}.{key_token}" if prefix else key_token
            collected.extend(_collect_significant_evidence_values(value[key], prefix=path))
        return collected

    if isinstance(value, (list, tuple, set, frozenset)):
        collected: list[dict[str, Any]] = []
        for item in value:
            collected.extend(_collect_significant_evidence_values(item, prefix=prefix))
        return collected

    normalized = _normalize_evidence_value(value)
    if normalized is None:
        return []
    return [{"path": prefix or "root", "value": normalized}]


FINGERPRINT_SCHEMA_VERSION = "finding-fingerprint/v2"


def build_finding_fingerprint(
    *,
    target: Any,
    title: Any,
    cwe: Any,
    evidence: Any,
    version: str = FINGERPRINT_SCHEMA_VERSION,
) -> str:
    canonical_evidence = {
        "keys": sorted(_collect_normalized_keys(evidence)),
        "values": sorted(
            _collect_significant_evidence_values(evidence),
            key=lambda item: _canonical_json(item),
        ),
    }
    payload = {
        "version": _normalize_token(version),
        "target": _normalize_token(target),
        "title": _normalize_token(title),
        "cwe": _normalize_token(cwe or ""),
        "evidence": canonical_evidence,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class Finding(BaseModel):
    """Represents one normalized security finding.

    Attributes:
        finding_id: Stable unique identifier.
        title: Short title for dashboards and logs.
        description: Human-readable explanation.
        severity: Standardized impact level.
        tool: Source tool/plugin name.
        target: Target identifier that produced this finding.
        cwe: Optional CWE identifier.
        cvss: Optional CVSS score if available.
        evidence: Arbitrary evidence payload.
        metadata: Additional structured context.
        created_at: UTC creation timestamp.
        fingerprint: Stable semantic fingerprint for dedupe/trends.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3)
    severity: SeverityLevel = Field(default=SeverityLevel.INFO)
    tool: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, description="IP/domain/url identifier.")
    cwe: str | None = Field(default=None)
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    fingerprint: str = Field(default="")

    @field_validator("title", "description", "tool", "target", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> str:
        """Normalize required text fields.

        Args:
            value: Candidate field value.

        Returns:
            str: Trimmed string.

        Raises:
            ValueError: If the value is empty after normalization.
        """

        text = str(value).strip()
        if not text:
            raise ValueError("Text fields must not be empty.")
        return text

    @model_validator(mode="after")
    def assign_fingerprint(self) -> "Finding":
        object.__setattr__(
            self,
            "fingerprint",
            build_finding_fingerprint(
                target=self.target,
                title=self.title,
                cwe=self.cwe,
                evidence=self.evidence,
            ),
        )
        return self

    @property
    def semantic_fingerprint(self) -> str:
        """Backward-compatible alias for stable finding fingerprint."""

        return self.fingerprint
