"""Circuit-breaker checks for preflight."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


async def check_preflight_circuit(
    manager: Any,
    *,
    tool_name: str,
    request: ScanRequest,
    started_at: datetime,
) -> ScanResult | None:
    """Return failure result if tool is currently quarantined."""
    if manager._circuit_breaker.is_quarantined(tool_name):
        reason = manager._circuit_breaker.quarantine_reason(tool_name) or "circuit_open"
        reason_code = "tool_quarantined"
        error_message = f"Tool is quarantined: {reason}"
        error_details = manager._runtime_error_details(
            reason_code=reason_code,
            stage="circuit_breaker",
            remediation="Wait for quarantine window to expire or reset breaker state.",
            context={"tool": tool_name, "quarantine": reason},
        )
        await manager._publish_tool_error_event(
            tool_name=tool_name,
            request=request,
            error=error_message,
            stage="circuit_breaker",
            reason="quarantined",
            reason_code=reason_code,
            extra={"quarantine": reason},
            error_details=error_details,
        )
        return manager._build_failure_result_for_reason(
            request=request,
            tool_name=tool_name,
            started_at=started_at,
            error_message=error_message,
            reason="quarantined",
            reason_code=reason_code,
            metadata={"quarantine": reason},
            error_details=error_details,
        )

    return None

