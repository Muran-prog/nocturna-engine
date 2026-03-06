"""Scan execution flow and phase DAG runtime integration."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from nocturna_engine.core.pipeline import ArtifactStore, PhaseDAGRunner, PhaseStep
from nocturna_engine.exceptions import (
    FingerprintIndexCorruptionError,
    FingerprintIndexIOError,
    PipelineError,
)
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest


class _EngineScanExecutionMixin:
    async def run_scan(self, request: ScanRequest) -> dict[str, Any]:
        """Execute full scan/analyze/report pipeline for one request.

        Args:
            request: Validated scan request.

        Returns:
            dict[str, Any]: Final pipeline context.

        Raises:
            RuntimeError: If the engine is draining (shutting down).
        """

        if not self._started:
            await self.start()

        if self._draining:
            raise RuntimeError(
                f"Engine is shutting down. Scan request '{request.request_id}' rejected."
            )

        scan_task = asyncio.current_task()
        if scan_task is not None:
            self._active_scans[request.request_id] = scan_task

        try:
            await self.event_bus.publish(
                "on_scan_started",
                {
                    "request_id": request.request_id,
                    "target_count": len(request.targets),
                    "tool_names": request.tool_names or [],
                },
            )

            initial_context: dict[str, Any] = {
                "request": request,
                "scan_started_at": datetime.now(UTC),
            }
            if self._is_phase_dag_enabled(request):
                final_context = await self._run_scan_with_phase_dag(initial_context)
            else:
                final_context = await self.pipeline.run(initial_context)

            findings = [
                finding
                for finding in final_context.get("findings", [])
                if isinstance(finding, Finding)
            ]
            try:
                trend_entries = self.finding_index.observe_findings(findings)
                final_context["finding_trends"] = {
                    finding.fingerprint: trend_entries[finding.fingerprint].to_dict()
                    for finding in findings
                    if finding.fingerprint in trend_entries
                }
                final_context["finding_trend_index_size"] = len(self.finding_index)
            except FingerprintIndexCorruptionError as exc:
                self.logger.error(
                    "finding_index_corrupt",
                    request_id=request.request_id,
                    error=str(exc),
                    exc_info=True,
                )
                await self.event_bus.publish(
                    "on_fingerprint_index_error",
                    {
                        "request_id": request.request_id,
                        "error_type": "corruption",
                        "error": str(exc),
                        "code": exc.code,
                    },
                )
                # Disable trending for THIS scan run only
                final_context["finding_trends"] = {}
                final_context["finding_trend_index_size"] = 0
                final_context["finding_trend_disabled"] = True
                final_context["finding_trend_disabled_reason"] = str(exc)
            except FingerprintIndexIOError as exc:
                self.logger.warning(
                    "finding_index_io_error",
                    request_id=request.request_id,
                    error=str(exc),
                    exc_info=True,
                )
                await self.event_bus.publish(
                    "on_fingerprint_index_error",
                    {
                        "request_id": request.request_id,
                        "error_type": "io_error",
                        "error": str(exc),
                        "code": exc.code,
                    },
                )
                # Transient — disable trending for this scan only
                final_context["finding_trends"] = {}
                final_context["finding_trend_index_size"] = 0
                final_context["finding_trend_disabled"] = True
                final_context["finding_trend_disabled_reason"] = str(exc)
            except Exception as exc:
                # Unexpected error — log as error, emit event, but don't crash scan
                self.logger.error(
                    "finding_index_unexpected_error",
                    request_id=request.request_id,
                    error=str(exc),
                    exc_info=True,
                )
                await self.event_bus.publish(
                    "on_fingerprint_index_error",
                    {
                        "request_id": request.request_id,
                        "error_type": "unexpected",
                        "error": str(exc),
                    },
                )
                final_context["finding_trends"] = {}
                final_context["finding_trend_index_size"] = 0
                final_context["finding_trend_disabled"] = True
                final_context["finding_trend_disabled_reason"] = str(exc)

            await self.event_bus.publish(
                "on_scan_finished",
                {
                    "request_id": request.request_id,
                    "result_count": len(final_context.get("scan_results", [])),
                    "finding_count": len(final_context.get("findings", [])),
                },
            )
            return final_context
        finally:
            self._active_scans.pop(request.request_id, None)

    def run_scan_sync(self, request: ScanRequest) -> dict[str, Any]:
        """Synchronous facade for async scan execution.

        Args:
            request: Validated scan request.

        Returns:
            dict[str, Any]: Final pipeline context.

        Raises:
            RuntimeError: If called from an existing running event loop.
        """

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.run_scan(request))
        raise RuntimeError("run_scan_sync cannot be used inside a running event loop.")

    async def _run_scan_with_phase_dag(self, initial_context: dict[str, Any]) -> dict[str, Any]:
        request: ScanRequest = initial_context["request"]
        runner = PhaseDAGRunner(
            logger=self.logger.bind(component="phase_dag_runner"),
            event_bus=self.event_bus,
        )
        phase_steps = self._build_phase_dag_steps(request)
        context = await runner.run(
            phase_steps,
            tool_handler=self._execute_phase_dag_step,
            initial_context=initial_context,
        )
        context.setdefault("scan_results", [])
        return await self._run_post_scan_steps(context)

    async def _execute_phase_dag_step(self, step: PhaseStep, context: dict[str, Any]) -> dict[str, Any]:
        request: ScanRequest = context["request"]
        result = await self.plugin_manager.execute_tool(step.tool, request)

        scan_results = context.setdefault("scan_results", [])
        if isinstance(scan_results, list):
            scan_results.append(result)

        artifacts = context.get("artifacts")
        if isinstance(artifacts, ArtifactStore):
            artifacts.put(step.phase, step.tool, "result", result)
            artifacts.put(step.phase, step.tool, "success", result.success)
            if result.raw_output is not None:
                artifacts.put(step.phase, step.tool, "raw_output", result.raw_output)
            if result.findings:
                artifacts.put(step.phase, step.tool, "findings", list(result.findings))

        if not result.success:
            error_message = result.error_message or "unknown execution error"
            raise PipelineError(
                f"Tool '{step.tool}' failed in phase '{step.phase}': {error_message}"
            )
        return {}

    async def _run_post_scan_steps(self, context: dict[str, Any]) -> dict[str, Any]:
        context.setdefault("errors", [])
        if context.get("scan_results"):
            try:
                context.update(await self._analyze_step(dict(context)))
            except Exception as exc:
                context["errors"].append({"step": "analyze", "error": str(exc)})
                self.logger.warning("pipeline_step_failed", step="analyze", error=str(exc))

        try:
            context.update(await self._report_step(dict(context)))
        except Exception as exc:
            context["errors"].append({"step": "report", "error": str(exc)})
            self.logger.warning("pipeline_step_failed", step="report", error=str(exc))
            request: ScanRequest = context["request"]
            scan_results = context.get("scan_results", [])
            findings = context.get("findings", [])
            errors = context.get("errors", [])
            context.setdefault(
                "reports",
                {
                    "summary": self._build_summary_report(
                        request=request,
                        scan_results=scan_results if isinstance(scan_results, list) else [],
                        findings=findings if isinstance(findings, list) else [],
                        errors=errors if isinstance(errors, list) else [],
                    )
                },
            )

        return context
