"""Error detail helpers for plugin system v2 execution flow."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.exceptions import build_error_details


class PluginV2ErrorHandlingMixin:
    """Error detail normalization helpers for plugin manager v2 flow."""

    @staticmethod
    def _error_category_for_stage(stage: str) -> str:
        mapping = {
            "policy": "policy",
            "adapter": "adapter",
            "setup": "plugin_setup",
            "execution": "execution",
            "circuit_breaker": "reliability",
            "preflight": "preflight",
        }
        return mapping.get(stage, "execution")

    @classmethod
    def _runtime_error_details(
        cls,
        *,
        reason_code: str,
        stage: str,
        retryable: bool = False,
        remediation: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return build_error_details(
            code=reason_code,
            category=cls._error_category_for_stage(stage),
            retryable=retryable,
            remediation=remediation,
            context=context,
        )

    @staticmethod
    def _with_error_fields(payload: Mapping[str, Any], error_details: Mapping[str, Any]) -> dict[str, Any]:
        context_value = error_details.get("context")
        details = build_error_details(
            code=str(error_details.get("code") or "execution_error"),
            category=str(error_details.get("category") or "execution"),
            retryable=bool(error_details.get("retryable", False)),
            remediation=(
                str(error_details["remediation"])
                if isinstance(error_details.get("remediation"), str)
                else None
            ),
            context=context_value if isinstance(context_value, Mapping) else None,
        )
        enriched = dict(payload)
        enriched["error_details"] = details
        enriched["code"] = details["code"]
        enriched["category"] = details["category"]
        enriched["retryable"] = details["retryable"]
        enriched["remediation"] = details["remediation"]
        enriched["context"] = dict(details["context"])
        return enriched

    @classmethod
    def _merge_error_context(
        cls,
        error_details: Mapping[str, Any],
        *,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        existing_context_value = error_details.get("context")
        merged_context: dict[str, Any] = {}
        if isinstance(existing_context_value, Mapping):
            merged_context.update({str(key): value for key, value in existing_context_value.items()})
        merged_context.update({str(key): value for key, value in context.items()})
        remediation_value = error_details.get("remediation")
        return build_error_details(
            code=str(error_details.get("code") or "execution_error"),
            category=str(error_details.get("category") or "execution"),
            retryable=bool(error_details.get("retryable", False)),
            remediation=str(remediation_value) if isinstance(remediation_value, str) else None,
            context=merged_context,
        )

    @classmethod
    def _normalize_existing_error_details(
        cls,
        details: Any,
        *,
        fallback_reason_code: str,
        stage: str,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if isinstance(details, Mapping):
            details_context = details.get("context")
            merged_context: dict[str, Any] = {}
            if isinstance(details_context, Mapping):
                merged_context.update({str(key): value for key, value in details_context.items()})
            if context is not None:
                merged_context.update({str(key): value for key, value in context.items()})
            remediation_value = details.get("remediation")
            return build_error_details(
                code=str(details.get("code") or fallback_reason_code),
                category=str(details.get("category") or cls._error_category_for_stage(stage)),
                retryable=bool(details.get("retryable", False)),
                remediation=str(remediation_value) if isinstance(remediation_value, str) else None,
                context=merged_context,
            )
        return cls._runtime_error_details(
            reason_code=fallback_reason_code,
            stage=stage,
            context=context,
        )
