"""Runtime limit helpers for plugin system v2 execution flow."""

from __future__ import annotations

import json
from typing import Any

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class PluginV2RuntimeLimitMixin:
    """Runtime limits and output bound enforcement for plugin manager v2 flow."""

    @staticmethod
    def _resolve_runtime_limits(
        *,
        request: ScanRequest,
        adapter: Any,
        policy_decision: Any,
        default_timeout_seconds: float,
    ) -> tuple[float, int, int | None]:
        tool_timeout = float(getattr(adapter.tool, "timeout_seconds", default_timeout_seconds))
        timeout_seconds = min(tool_timeout, float(request.timeout_seconds))
        if policy_decision.effective_timeout_seconds is not None:
            timeout_seconds = min(timeout_seconds, float(policy_decision.effective_timeout_seconds))
        timeout_seconds = max(0.01, timeout_seconds)

        tool_retries = int(min(getattr(adapter.tool, "max_retries", request.retries), request.retries))
        if policy_decision.effective_retries is None:
            retries = tool_retries
        else:
            retries = min(tool_retries, int(policy_decision.effective_retries))
        retries = max(0, retries)

        max_output_bytes: int | None = None
        if policy_decision.effective_max_output_bytes is not None:
            max_output_bytes = max(1, int(policy_decision.effective_max_output_bytes))

        return timeout_seconds, retries, max_output_bytes

    @staticmethod
    def _estimate_result_output_bytes(result: ScanResult) -> int:
        payload = {
            "raw_output": result.raw_output,
            "findings": [finding.model_dump(mode="json") for finding in result.findings],
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
        return len(serialized.encode("utf-8"))

    def _enforce_output_limit(
        self,
        *,
        result: ScanResult,
        tool_name: str,
        max_output_bytes: int | None,
    ) -> dict[str, Any] | None:
        observed_bytes = self._estimate_result_output_bytes(result)
        result.metadata = {
            **result.metadata,
            "observed_output_bytes": observed_bytes,
        }
        if max_output_bytes is None:
            return None

        result.metadata = {
            **result.metadata,
            "effective_max_output_bytes": max_output_bytes,
        }
        if observed_bytes <= max_output_bytes:
            return None

        reason = "output_limit_exceeded"
        error_details = self._runtime_error_details(
            reason_code=reason,
            stage="execution",
            retryable=False,
            remediation="Reduce scope or increase policy max_output_bytes.",
            context={
                "tool": tool_name,
                "observed_output_bytes": observed_bytes,
                "effective_max_output_bytes": max_output_bytes,
            },
        )
        result.success = False
        result.error_message = (
            f"Tool output exceeded max_output_bytes ({observed_bytes} > {max_output_bytes})."
        )
        result.raw_output = {
            "truncated": True,
            "reason": reason,
            "observed_output_bytes": observed_bytes,
            "effective_max_output_bytes": max_output_bytes,
        }
        result.findings = []
        result.metadata = self._with_error_metadata(
            metadata=result.metadata,
            reason=reason,
            reason_code=reason,
            error_details=error_details,
        )
        return error_details
