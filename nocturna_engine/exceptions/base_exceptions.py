"""Custom exception hierarchy for Nocturna Engine.

Centralized exceptions make error handling explicit and predictable across
plugin orchestration, event processing, and pipeline execution.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class ErrorDetails:
    """Structured error payload used by metadata/events integration."""

    code: str
    category: str
    retryable: bool = False
    remediation: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Serialize details into plain JSON-safe mapping."""

        return {
            "code": self.code,
            "category": self.category,
            "retryable": self.retryable,
            "remediation": self.remediation,
            "context": dict(self.context),
        }


def _normalize_context(context: Mapping[str, Any] | None) -> dict[str, Any]:
    if context is None:
        return {}
    return {str(key): value for key, value in context.items()}


def build_error_details(
    *,
    code: str,
    category: str,
    retryable: bool = False,
    remediation: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build normalized structured error details."""

    normalized_code = code.strip() or "runtime_error"
    normalized_category = category.strip() or "runtime"
    details = ErrorDetails(
        code=normalized_code,
        category=normalized_category,
        retryable=bool(retryable),
        remediation=remediation,
        context=_normalize_context(context),
    )
    return details.as_dict()


def error_details_from_exception(
    error: BaseException,
    *,
    default_code: str = "runtime_error",
    default_category: str = "runtime",
    default_retryable: bool = False,
    default_remediation: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract structured details from known engine exceptions."""

    merged_context = _normalize_context(context)
    if isinstance(error, NocturnaError):
        base = error.to_error_dict()
        base_context = base.get("context")
        if isinstance(base_context, Mapping):
            merged_context = {**_normalize_context(base_context), **merged_context}
        return build_error_details(
            code=str(base.get("code") or default_code),
            category=str(base.get("category") or default_category),
            retryable=bool(base.get("retryable", default_retryable)),
            remediation=str(base["remediation"]) if isinstance(base.get("remediation"), str) else default_remediation,
            context=merged_context,
        )
    return build_error_details(
        code=default_code,
        category=default_category,
        retryable=default_retryable,
        remediation=default_remediation,
        context=merged_context,
    )


class NocturnaError(Exception):
    """Base exception for all engine-specific failures."""

    default_code = "nocturna_error"
    default_category = "runtime"
    default_retryable = False
    default_remediation: str | None = None

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        category: str | None = None,
        retryable: bool | None = None,
        remediation: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        normalized_code = (code or self.default_code).strip() or self.default_code
        normalized_category = (category or self.default_category).strip() or self.default_category
        normalized_message = (message or normalized_code).strip() or normalized_code
        super().__init__(normalized_message)

        self.message = normalized_message
        self._details = ErrorDetails(
            code=normalized_code,
            category=normalized_category,
            retryable=self.default_retryable if retryable is None else bool(retryable),
            remediation=remediation if remediation is not None else self.default_remediation,
            context=_normalize_context(context),
        )

    @property
    def code(self) -> str:
        return self._details.code

    @property
    def category(self) -> str:
        return self._details.category

    @property
    def retryable(self) -> bool:
        return self._details.retryable

    @property
    def remediation(self) -> str | None:
        return self._details.remediation

    @property
    def context(self) -> dict[str, Any]:
        return dict(self._details.context)

    def to_error_dict(self) -> dict[str, Any]:
        """Serialize structured fields for metadata/events propagation."""

        return self._details.as_dict()


class ConfigError(NocturnaError):
    """Raised when configuration cannot be loaded or validated."""

    default_code = "config_error"
    default_category = "configuration"
    default_remediation = "Fix runtime configuration and retry."


class ValidationError(NocturnaError):
    """Raised when user input or internal data validation fails."""

    default_code = "validation_error"
    default_category = "validation"
    default_remediation = "Validate input payload and retry with corrected values."


class PluginError(NocturnaError):
    """Base exception for plugin lifecycle and execution issues."""

    default_code = "plugin_error"
    default_category = "plugin"


class PluginRegistrationError(PluginError):
    """Raised when a plugin class fails registry validation."""

    default_code = "plugin_registration_error"
    default_category = "plugin_registration"
    default_remediation = "Fix plugin metadata/manifest and register again."


class PluginExecutionError(PluginError):
    """Raised when plugin execution fails in a non-recoverable way."""

    default_code = "plugin_execution_error"
    default_category = "plugin_execution"
    default_remediation = "Inspect plugin logs, target, and runtime context."


class EventBusError(NocturnaError):
    """Raised for event bus subscription or delivery failures."""

    default_code = "event_bus_error"
    default_category = "event_bus"
    default_retryable = True
    default_remediation = "Retry event publish/subscribe operation."


class PipelineError(NocturnaError):
    """Raised when pipeline execution cannot proceed safely."""

    default_code = "pipeline_error"
    default_category = "pipeline"
    default_remediation = "Inspect pipeline steps and dependency availability."


class SecretNotFoundError(NocturnaError):
    """Raised when a required secret is unavailable in env/keyring."""

    default_code = "secret_not_found"
    default_category = "secrets"
    default_remediation = "Provide required secret in environment/keyring and retry."


class NocturnaTimeoutError(NocturnaError):
    """Raised when an async operation exceeds the configured timeout."""

    default_code = "timeout"
    default_category = "timeout"
    default_retryable = True
    default_remediation = "Increase timeout or reduce workload scope and retry."
