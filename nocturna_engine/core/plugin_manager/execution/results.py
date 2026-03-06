"""Result helpers for plugin execution."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from nocturna_engine.exceptions import build_error_details, error_details_from_exception
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class PluginExecutionResultMixin:
    """Standardized result builders for execution flows."""

    @staticmethod
    def _calculate_duration_ms(*, started_at: datetime, finished_at: datetime) -> int:
        """Compute non-negative duration in milliseconds."""

        return max(0, int((finished_at - started_at).total_seconds() * 1000))

    @classmethod
    def _finalize_result_timing(
        cls,
        *,
        result: ScanResult,
        started_at: datetime,
        finished_at: datetime | None = None,
    ) -> ScanResult:
        """Set started/finished timestamps and duration using shared timing rules."""

        resolved_finished_at = finished_at or datetime.now(UTC)
        result.started_at = started_at
        result.finished_at = resolved_finished_at
        result.duration_ms = cls._calculate_duration_ms(started_at=started_at, finished_at=resolved_finished_at)
        return result

    @staticmethod
    def _with_error_metadata(
        *,
        metadata: Mapping[str, Any] | None,
        reason: str,
        reason_code: str,
        error_details: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Attach canonical reason fields and normalized error details to metadata."""

        return {
            **dict(metadata or {}),
            "reason": reason,
            "reason_code": reason_code,
            "error": dict(error_details),
        }

    @classmethod
    def _build_failure_result_for_reason(
        cls,
        *,
        request: ScanRequest,
        tool_name: str,
        started_at: datetime,
        error_message: str,
        reason: str,
        reason_code: str,
        error_details: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
        error: BaseException | None = None,
    ) -> ScanResult:
        """Build a failed result with canonical error metadata fields."""

        return cls._build_failure_result(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=error_message,
            metadata=cls._with_error_metadata(
                metadata=metadata,
                reason=reason,
                reason_code=reason_code,
                error_details=error_details,
            ),
            error=error,
            error_details=error_details,
        )

    @classmethod
    def _build_failure_result(
        cls,
        request: ScanRequest,
        tool_name: str,
        started_at: datetime,
        error_message: str,
        metadata: Mapping[str, Any] | None = None,
        *,
        error: BaseException | None = None,
        error_details: Mapping[str, Any] | None = None,
    ) -> ScanResult:
        """Build failed result payload."""

        finished_at = datetime.now(UTC)
        metadata_payload = dict(metadata or {})
        resolved_error = PluginExecutionResultMixin._normalize_error_details(
            error_message=error_message,
            metadata=metadata_payload,
            error=error,
            error_details=error_details,
        )
        result_metadata: dict[str, Any] = {
            "degraded": True,
            **metadata_payload,
            "error": resolved_error,
        }
        reason = result_metadata.get("reason")
        if not isinstance(reason, str) or not reason:
            result_metadata["reason"] = error_message
        reason_code = result_metadata.get("reason_code")
        if not isinstance(reason_code, str) or not reason_code:
            result_metadata["reason_code"] = str(resolved_error.get("code") or "execution_error")

        return ScanResult(
            request_id=request.request_id,
            tool_name=tool_name,
            success=False,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=cls._calculate_duration_ms(started_at=started_at, finished_at=finished_at),
            error_message=error_message,
            metadata=result_metadata,
        )

    @staticmethod
    def _normalize_error_details(
        *,
        error_message: str,
        metadata: Mapping[str, Any],
        error: BaseException | None,
        error_details: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        context_value = metadata.get("context")
        context = context_value if isinstance(context_value, Mapping) else None
        remediation_value = metadata.get("remediation")
        remediation = remediation_value if isinstance(remediation_value, str) else None
        category_value = metadata.get("category")
        category = category_value if isinstance(category_value, str) else "execution"
        reason_code_value = metadata.get("reason_code")
        code = reason_code_value if isinstance(reason_code_value, str) and reason_code_value else "execution_error"
        retryable_value = metadata.get("retryable")
        retryable = bool(retryable_value) if isinstance(retryable_value, bool) else False

        if error_details is not None:
            return build_error_details(
                code=str(error_details.get("code") or code),
                category=str(error_details.get("category") or category),
                retryable=bool(error_details.get("retryable", retryable)),
                remediation=(
                    str(error_details["remediation"])
                    if isinstance(error_details.get("remediation"), str)
                    else remediation
                ),
                context=(
                    error_details.get("context")
                    if isinstance(error_details.get("context"), Mapping)
                    else context
                ),
            )

        if error is not None:
            return error_details_from_exception(
                error,
                default_code=code,
                default_category=category,
                default_retryable=retryable,
                default_remediation=remediation,
                context=context,
            )

        return build_error_details(
            code=code,
            category=category,
            retryable=retryable,
            remediation=remediation,
            context=context,
        )
