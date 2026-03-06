"""Completion stage for v2 single-tool execution."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


async def publish_tool_completion(
    manager: Any,
    *,
    tool_name: str,
    request: ScanRequest,
    result: ScanResult,
) -> None:
    """Publish completion events for a finished tool execution."""
    if result.success:
        for finding in result.findings:
            await manager._event_bus.publish(
                "on_raw_finding_detected",
                {
                    "tool": tool_name,
                    "request_id": request.request_id,
                    "severity": finding.severity.value,
                    "finding_id": finding.finding_id,
                    "finding_fingerprint": finding.fingerprint,
                },
            )

    finished_payload: dict[str, Any] = {
        "tool": tool_name,
        "request_id": request.request_id,
        "success": result.success,
        "duration_ms": result.duration_ms,
    }
    reason = result.metadata.get("reason")
    reason_code = result.metadata.get("reason_code")
    if isinstance(reason, str) and reason:
        finished_payload["reason"] = reason
    if isinstance(reason_code, str) and reason_code:
        finished_payload["reason_code"] = reason_code

    result_error = result.metadata.get("error")
    if isinstance(result_error, Mapping):
        finished_payload = manager._with_error_fields(finished_payload, result_error)

    await manager._event_bus.publish("on_tool_finished", finished_payload)
