"""Pipeline step implementations for Nocturna Engine."""

from __future__ import annotations

import functools
from typing import Any

from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, retry_async, with_timeout


async def _run_analyzer(
    analyzer: Any,
    scan_results: list[ScanResult],
    request: ScanRequest,
) -> list[Finding]:
    """Eagerly-bound analyzer invocation for safe deferred execution."""
    return await with_timeout(
        analyzer.analyze(scan_results, request),
        timeout_seconds=request.timeout_seconds,
        operation_name=f"analyzer:{analyzer.name}",
    )


async def _run_reporter(
    reporter: Any,
    request: ScanRequest,
    scan_results: list[ScanResult],
    findings: list[Finding],
) -> dict[str, Any]:
    """Eagerly-bound reporter invocation for safe deferred execution."""
    return await with_timeout(
        reporter.generate_report(request, scan_results, findings),
        timeout_seconds=request.timeout_seconds,
        operation_name=f"reporter:{reporter.name}",
    )


class _EngineSteps:
    def _deduplicate_findings_by_fingerprint(
        self,
        findings: list[Finding],
        *,
        stage: str,
        request_id: str,
    ) -> list[Finding]:
        deduplicated: dict[str, Finding] = {}
        for finding in findings:
            existing = deduplicated.get(finding.fingerprint)
            if existing is not None:
                self.logger.warning(
                    "finding_fingerprint_collision",
                    stage=stage,
                    request_id=request_id,
                    fingerprint=finding.fingerprint,
                    previous_finding_id=existing.finding_id,
                    replacement_finding_id=finding.finding_id,
                )
                deduplicated.pop(finding.fingerprint, None)
            deduplicated[finding.fingerprint] = finding
        return list(deduplicated.values())

    async def _scan_step(self, context: dict[str, Any]) -> dict[str, Any]:
        """Run all selected plugins and return raw results.

        Args:
            context: Pipeline context.

        Returns:
            dict[str, Any]: Context update containing `scan_results`.
        """

        request: ScanRequest = context["request"]
        results = await self.plugin_manager.execute_all(request=request, tool_names=request.tool_names)
        return {"scan_results": results}

    async def _analyze_step(self, context: dict[str, Any]) -> dict[str, Any]:
        """Aggregate and enrich findings from scan results.

        Args:
            context: Pipeline context.

        Returns:
            dict[str, Any]: Context update containing `findings`.
        """

        request: ScanRequest = context["request"]
        scan_results: list[ScanResult] = context.get("scan_results", [])
        merged_findings: list[Finding] = [finding for result in scan_results for finding in result.findings]

        for analyzer in self._analyzers:
            try:
                generated = await retry_async(
                    functools.partial(_run_analyzer, analyzer, scan_results, request),
                    retries=request.retries,
                    retry_exceptions=TRANSIENT_RETRY_EXCEPTIONS,
                )
                merged_findings.extend(generated)
            except Exception as exc:
                self.logger.warning(
                    "analyzer_failed",
                    analyzer=analyzer.name,
                    request_id=request.request_id,
                    error=str(exc),
                )
                await self.event_bus.publish(
                    "on_analyzer_error",
                    {
                        "analyzer": analyzer.name,
                        "request_id": request.request_id,
                        "error": str(exc),
                    },
                )

        unique_findings = self._deduplicate_findings_by_fingerprint(
            merged_findings,
            stage="analyze",
            request_id=request.request_id,
        )
        for finding in unique_findings:
            await self.event_bus.publish(
                "on_finding_detected",
                {
                    "request_id": request.request_id,
                    "finding_id": finding.finding_id,
                    "severity": finding.severity.value,
                    "fingerprint": finding.fingerprint,
                },
            )
        return {"findings": unique_findings}

    async def _report_step(self, context: dict[str, Any]) -> dict[str, Any]:
        """Generate report payloads from findings.

        Args:
            context: Pipeline context.

        Returns:
            dict[str, Any]: Context update containing `reports`.
        """

        request: ScanRequest = context["request"]
        scan_results: list[ScanResult] = context.get("scan_results", [])
        findings_input = context.get("findings", [])
        findings: list[Finding] = self._deduplicate_findings_by_fingerprint(
            findings_input if isinstance(findings_input, list) else [],
            stage="report",
            request_id=request.request_id,
        )
        reports: dict[str, Any] = {}

        if self._reporters:
            for reporter in self._reporters:
                try:
                    report_payload = await retry_async(
                        functools.partial(_run_reporter, reporter, request, scan_results, findings),
                        retries=request.retries,
                    retry_exceptions=TRANSIENT_RETRY_EXCEPTIONS,
                    )
                    reports[reporter.name] = report_payload
                except Exception as exc:
                    self.logger.warning(
                        "reporter_failed",
                        reporter=reporter.name,
                        request_id=request.request_id,
                        error=str(exc),
                    )
                    await self.event_bus.publish(
                        "on_reporter_error",
                        {
                            "reporter": reporter.name,
                            "request_id": request.request_id,
                            "error": str(exc),
                        },
                    )

        if not reports:
            reports["summary"] = self._build_summary_report(request, scan_results, findings, context.get("errors", []))

        return {"reports": reports}
