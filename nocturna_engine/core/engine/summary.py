"""Summary report helpers for Nocturna Engine."""

from __future__ import annotations

from collections import Counter
from typing import Any

from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class _EngineSummary:
    @staticmethod
    def _build_summary_report(
        request: ScanRequest,
        scan_results: list[ScanResult],
        findings: list[Finding],
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Build fallback summary report when reporters are absent.

        Args:
            request: Original request.
            scan_results: Tool results.
            findings: Final findings list.
            errors: Pipeline error entries.

        Returns:
            dict[str, Any]: Summary report.
        """

        severity_counter = Counter(item.severity.value for item in findings)
        return {
            "request_id": request.request_id,
            "targets": [target.model_dump(mode="json") for target in request.targets],
            "tools_executed": [result.tool_name for result in scan_results],
            "successful_tools": [result.tool_name for result in scan_results if result.success],
            "failed_tools": [result.tool_name for result in scan_results if not result.success],
            "findings_total": len(findings),
            "findings_by_severity": dict(severity_counter),
            "errors": errors,
        }
