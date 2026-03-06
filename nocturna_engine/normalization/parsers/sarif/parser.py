"""SARIF v2.1.0 parser for Static Analysis Results Interchange Format."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import structlog

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseParser, ParseResult, ParserConfig
from nocturna_engine.normalization.errors import ParseError
from nocturna_engine.normalization.parsers.sarif.extractors import (
    build_rule_index,
    build_sarif_evidence,
    extract_cwe,
    extract_cvss,
    extract_message,
    extract_target,
    extract_tool_name,
    is_suppressed,
    resolve_severity,
)
from nocturna_engine.normalization.registry import register_parser

logger = structlog.get_logger("normalization.parser.sarif")


@register_parser(
    name="sarif",
    formats=[InputFormat.SARIF],
    tool_patterns=["sarif*", "semgrep*", "codeql*", "eslint*", "bandit*"],
    priority=10,
)
class SarifParser(BaseParser):
    """Parser for SARIF v2.1.0 static analysis output.

    Handles the standard SARIF JSON structure:
    ``$.runs[].results[]`` — individual findings
    ``$.runs[].tool.driver.rules[]`` — rule metadata for severity/CWE enrichment
    ``$.runs[].tool.extensions[].rules[]`` — extension rules (CodeQL query packs)
    """

    parser_name = "sarif"
    source_format = "sarif_v2.1.0"

    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete SARIF JSON data.

        Args:
            data: Complete SARIF JSON payload.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        stats = NormalizationStats()

        try:
            sarif_doc = json.loads(text)
        except json.JSONDecodeError as exc:
            issue = self._make_issue(
                f"Invalid SARIF JSON: {exc}",
                error=exc,
            )
            stats.errors_encountered += 1
            return ParseResult(issues=[issue], stats=stats)

        if not isinstance(sarif_doc, dict):
            issue = self._make_issue("SARIF root is not a JSON object.")
            stats.errors_encountered += 1
            return ParseResult(issues=[issue], stats=stats)

        return self._extract_from_document(sarif_doc, stats=stats)

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse SARIF from a byte stream by accumulating chunks.

        SARIF is a single JSON document, so streaming requires buffering.
        For very large SARIF files, the ijson approach would be better,
        but standard SARIF files are typically within reasonable memory bounds.

        Args:
            stream: Async byte chunk iterator.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        chunks: list[bytes] = []
        accumulated_size = 0
        max_bytes = self._config.max_input_bytes
        async for chunk in stream:
            accumulated_size += len(chunk)
            if accumulated_size > max_bytes:
                raise ParseError(
                    f"SARIF input exceeds maximum allowed size ({max_bytes} bytes).",
                    source_parser=self.parser_name,
                )
            chunks.append(chunk)
        full_data = b"".join(chunks)
        return await self.parse(full_data)

    def _extract_from_document(
        self,
        doc: dict[str, Any],
        *,
        stats: NormalizationStats,
    ) -> ParseResult:
        """Extract findings from a parsed SARIF document."""
        findings: list[Finding] = []
        issues = list(self._validate_sarif_structure(doc))

        runs = doc.get("runs")
        if not isinstance(runs, list):
            return ParseResult(findings=findings, issues=issues, stats=stats)

        for run_index, run in enumerate(runs):
            if not isinstance(run, dict):
                issues.append(self._make_issue(
                    f"Run at index {run_index} is not an object.",
                ))
                continue

            # Build rule index for severity/CWE enrichment.
            rule_index = build_rule_index(run)
            tool_name = extract_tool_name(run, fallback=self._config.tool_name)
            results = run.get("results")
            if not isinstance(results, list):
                continue

            for result_index, result in enumerate(results):
                stats.total_records_processed += 1
                if not isinstance(result, dict):
                    stats.errors_encountered += 1
                    issues.append(self._make_issue(
                        f"Result at run[{run_index}].results[{result_index}] is not an object.",
                    ))
                    continue

                # Suppression handling: skip accepted suppressions.
                suppressed, suppression_reason = is_suppressed(result)
                if suppressed:
                    stats.records_skipped += 1
                    self._logger.info(
                        "sarif_result_suppressed",
                        run_index=run_index,
                        result_index=result_index,
                        rule_id=result.get("ruleId", ""),
                        reason=suppression_reason,
                    )
                    continue

                try:
                    finding = self._result_to_finding(
                        result,
                        rule_index=rule_index,
                        tool_name=tool_name,
                        run_index=run_index,
                        result_index=result_index,
                    )
                    findings.append(finding)
                    stats.findings_produced += 1
                except (RecursionError, MemoryError):
                    raise
                except Exception as exc:
                    stats.errors_encountered += 1
                    logger.warning(
                        "sarif_result_conversion_failed",
                        run_index=run_index,
                        result_index=result_index,
                        error=str(exc),
                        exc_info=True,
                    )
                    issues.append(self._make_issue(
                        f"Failed to convert result at run[{run_index}].results[{result_index}]: {exc}",
                        raw_record=result,
                        error=exc,
                    ))
        stats.records_skipped += stats.total_records_processed - stats.findings_produced - stats.errors_encountered - stats.records_skipped
        return ParseResult(findings=findings, issues=issues, stats=stats)

    def _validate_sarif_structure(self, doc: dict[str, Any]) -> list:
        """Basic SARIF structure validation."""
        issues = []
        version = doc.get("version", "")
        if version and not str(version).startswith("2.1"):
            issues.append(self._make_issue(
                f"Unexpected SARIF version: {version}. Expected 2.1.x.",
            ))
        if "runs" not in doc:
            issues.append(self._make_issue("SARIF document missing 'runs' array."))
        return issues

    def _result_to_finding(
        self,
        result: dict[str, Any],
        *,
        rule_index: dict[str, dict[str, Any]],
        tool_name: str,
        run_index: int,
        result_index: int,
    ) -> Finding:
        """Convert one SARIF result to a Finding."""
        rule_id = str(result.get("ruleId", ""))
        rule_meta = rule_index.get(rule_id, {})

        # Title: message.text > rule.shortDescription.text > ruleId.
        title = extract_message(result)
        if not title:
            short_desc = rule_meta.get("shortDescription")
            if isinstance(short_desc, dict):
                title = str(short_desc.get("text", "")).strip()
        if not title:
            title = rule_id or f"SARIF finding at run[{run_index}].results[{result_index}]"

        # Description: rule.fullDescription.text > rule.help.text > message.text.
        description = ""
        full_desc = rule_meta.get("fullDescription")
        if isinstance(full_desc, dict):
            description = str(full_desc.get("text", "")).strip()
        if not description:
            help_text = rule_meta.get("help")
            if isinstance(help_text, dict):
                description = str(help_text.get("text", "")).strip()
        if not description:
            description = title

        # Severity mapping.
        severity = resolve_severity(
            result,
            rule_meta,
            config=self._config,
            tool_name=tool_name,
        )

        # Target: from location URI or config hint.
        target = extract_target(result, fallback=self._config.target_hint or "unknown")

        # CWE extraction from rule properties or taxa.
        cwe = extract_cwe(result, rule_meta)

        # CVSS from rule properties.
        cvss = extract_cvss(rule_meta)

        # Evidence.
        evidence = build_sarif_evidence(result, rule_id=rule_id)

        raw_level = str(result.get("level", "warning")).strip().lower()
        origin = self._build_origin(
            original_severity=raw_level,
            original_record=result if self._config.preserve_raw else None,
        )

        finding = Finding(
            title=title[:200],
            description=description,
            severity=severity,
            tool=tool_name,
            target=target,
            cwe=cwe,
            cvss=cvss,
            evidence=evidence,
        )
        return self._attach_origin(finding, origin)
