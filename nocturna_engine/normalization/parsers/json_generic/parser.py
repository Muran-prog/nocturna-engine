"""Generic JSON parser with tool-specific field mapping heuristics."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import structlog

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseParser, ParseResult, ParserConfig
from nocturna_engine.normalization.errors import ParseError
from nocturna_engine.normalization.parsers.json_generic.field_mapping import (
    _TOOL_FIELD_MAPS,
    _deep_get,
    _detect_tool_shape,
    _first_non_empty,
)
from nocturna_engine.normalization.registry import register_parser

logger = structlog.get_logger("normalization.parser.json_generic")


@register_parser(
    name="json_generic",
    formats=[InputFormat.JSON],
    tool_patterns=["nuclei*", "semgrep*", "subfinder*", "httpx*"],
    priority=5,
)
class GenericJsonParser(BaseParser):
    """Parser for generic JSON output from security tools.

    Handles both JSON objects (single result) and JSON arrays (multiple results).
    Uses heuristic field mapping for known tools, with a fallback for unknown shapes.
    """

    parser_name = "json_generic"
    source_format = "json"

    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete JSON data.

        Args:
            data: Complete JSON payload.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        stats = NormalizationStats()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            issue = self._make_issue(f"Invalid JSON: {exc}", error=exc)
            stats.errors_encountered += 1
            return ParseResult(issues=[issue], stats=stats)
        except RecursionError:
            issue = self._make_issue(
                "JSON parsing failed: document exceeds maximum nesting depth.",
            )
            stats.errors_encountered += 1
            return ParseResult(issues=[issue], stats=stats)

        records: list[dict[str, Any]]
        if isinstance(parsed, dict):
            # Check if it wraps results in a known container key.
            records = self._unwrap_results(parsed)
        elif isinstance(parsed, list):
            records = [r for r in parsed if isinstance(r, dict)]
        else:
            issue = self._make_issue("JSON root is neither object nor array.")
            stats.errors_encountered += 1
            return ParseResult(issues=[issue], stats=stats)

        return self._process_records(records, stats=stats)

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse JSON from a byte stream by accumulating chunks.

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
                    f"JSON input exceeds maximum allowed size ({max_bytes} bytes).",
                    source_parser=self.parser_name,
                )
            chunks.append(chunk)
        full_data = b"".join(chunks)
        return await self.parse(full_data)

    def _unwrap_results(self, obj: dict[str, Any]) -> list[dict[str, Any]]:
        """Attempt to unwrap a results array from a container object."""
        # Common container keys used by various tools.
        for key in ("results", "findings", "vulnerabilities", "matches", "issues", "data"):
            value = obj.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        # If no container found, treat the object itself as a single record.
        return [obj]

    def _process_records(
        self,
        records: list[dict[str, Any]],
        *,
        stats: NormalizationStats,
    ) -> ParseResult:
        """Process a list of JSON records into findings."""
        findings: list[Finding] = []
        issues = []

        for index, record in enumerate(records):
            stats.total_records_processed += 1
            try:
                finding = self._record_to_finding(record, index=index)
                if finding is not None:
                    findings.append(finding)
                    stats.findings_produced += 1
                else:
                    stats.records_skipped += 1
            except Exception as exc:
                stats.errors_encountered += 1
                issues.append(self._make_issue(
                    f"Failed to convert record at index {index}: {exc}",
                    raw_record=record,
                    error=exc,
                ))

        return ParseResult(findings=findings, issues=issues, stats=stats)

    def _record_to_finding(
        self,
        record: dict[str, Any],
        *,
        index: int,
    ) -> Finding | None:
        """Convert one JSON record to a Finding using tool-specific field mapping."""
        # Detect tool shape.
        tool_shape = _detect_tool_shape(record)
        field_map = _TOOL_FIELD_MAPS.get(tool_shape or "", {})

        # Extract fields.
        title = _first_non_empty(record, field_map.get("title_fields", []))  # type: ignore[arg-type]
        if not title:
            # Fallback: try common generic field names.
            title = _first_non_empty(record, ["title", "name", "vulnerability", "finding", "rule_id", "id"])
        if not title:
            return None  # Skip records that don't look like findings.

        description = _first_non_empty(record, field_map.get("description_fields", []))  # type: ignore[arg-type]
        if not description:
            description = _first_non_empty(record, ["description", "detail", "message", "summary"])
        if not description:
            description = title

        raw_severity = _first_non_empty(record, field_map.get("severity_fields", []))  # type: ignore[arg-type]
        if not raw_severity:
            raw_severity = _first_non_empty(record, ["severity", "risk", "priority", "level"])
        severity = self._config.severity_map.resolve(
            raw_severity or "info",
            tool_name=self._config.tool_name,
        )

        target = _first_non_empty(record, field_map.get("target_fields", []))  # type: ignore[arg-type]
        if not target:
            target = _first_non_empty(record, ["target", "host", "url", "ip", "address", "matched-at"])
        if not target:
            target = self._config.target_hint or "unknown"

        cwe = _first_non_empty(record, field_map.get("cwe_fields", []))  # type: ignore[arg-type]
        if not cwe:
            cwe = _first_non_empty(record, ["cwe", "cwe_id"]) or None

        cvss: float | None = None
        cvss_str = _first_non_empty(record, field_map.get("cvss_fields", []))  # type: ignore[arg-type]
        if not cvss_str:
            cvss_str = _first_non_empty(record, ["cvss", "cvss_score", "cvssScore"])
        if cvss_str:
            try:
                score = float(cvss_str)
                if 0.0 <= score <= 10.0:
                    cvss = score
            except (ValueError, TypeError):
                pass

        # Build evidence from designated fields.
        evidence = self._build_evidence(record, field_map)

        origin = self._build_origin(
            original_severity=raw_severity or None,
            original_record=record if self._config.preserve_raw else None,
        )

        finding = Finding(
            title=title[:200],
            description=description,
            severity=severity,
            tool=self._config.tool_name,
            target=target,
            cwe=cwe,
            cvss=cvss,
            evidence=evidence,
        )
        return self._attach_origin(finding, origin)

    def _build_evidence(
        self,
        record: dict[str, Any],
        field_map: dict[str, Any],
    ) -> dict[str, Any]:
        """Build evidence dict from record using field map hints."""
        evidence: dict[str, Any] = {}
        include_fields = field_map.get("evidence_include", [])
        if isinstance(include_fields, list):
            for field_path in include_fields:
                value = _deep_get(record, field_path)
                if value is not None:
                    # Use the last segment of the dotted path as key.
                    key = field_path.rsplit(".", 1)[-1]
                    evidence[key] = value
        return evidence
