"""Generic CSV parser with automatic header detection and field mapping."""

from __future__ import annotations

import csv
import io
from collections.abc import AsyncIterator
from typing import Any

import structlog

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseParser, ParseResult, ParserConfig
from nocturna_engine.normalization.parsers.csv_generic.column_mapping import (
    _COLUMN_ALIASES,
    _find_column,
)
from nocturna_engine.normalization.registry import register_parser

logger = structlog.get_logger("normalization.parser.csv_generic")


@register_parser(
    name="csv_generic",
    formats=[InputFormat.CSV],
    tool_patterns=["nikto*", "openvas*", "nessus*"],
    priority=5,
)
class GenericCsvParser(BaseParser):
    """Parser for CSV/TSV security tool output with automatic header detection.

    Detects column mapping by matching header names against known aliases.
    Supports both comma and tab delimiters.
    """

    parser_name = "csv_generic"
    source_format = "csv"

    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete CSV data.

        Args:
            data: Complete CSV payload.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        stats = NormalizationStats()

        # Detect delimiter.
        delimiter = self._detect_delimiter(text)

        reader = csv.reader(io.StringIO(text), delimiter=delimiter)

        # First row is header.
        try:
            raw_headers = next(reader)
        except StopIteration:
            return ParseResult(stats=stats)

        headers = [h.strip().lower() for h in raw_headers]
        column_map = self._build_column_map(headers)

        findings: list[Finding] = []
        issues = []

        for row_index, row in enumerate(reader, start=2):
            stats.total_records_processed += 1
            if not any(cell.strip() for cell in row):
                stats.records_skipped += 1
                continue

            try:
                finding = self._row_to_finding(row, column_map=column_map, row_number=row_index)
                if finding is not None:
                    findings.append(finding)
                    stats.findings_produced += 1
                else:
                    stats.records_skipped += 1
            except Exception as exc:
                stats.errors_encountered += 1
                issues.append(self._make_issue(
                    f"Failed to convert CSV row {row_index}: {exc}",
                    line_number=row_index,
                    error=exc,
                ))

        return ParseResult(findings=findings, issues=issues, stats=stats)

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse CSV from a streaming byte source.

        Accumulates chunks since CSV requires header context for all rows.

        Args:
            stream: Async byte chunk iterator.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        chunks: list[bytes] = []
        async for chunk in stream:
            chunks.append(chunk)
        full_data = b"".join(chunks)
        return await self.parse(full_data)

    def _detect_delimiter(self, text: str) -> str:
        """Detect whether input uses comma or tab delimiter."""
        first_line = text.split("\n", 1)[0]
        if first_line.count("\t") > first_line.count(","):
            return "\t"
        return ","

    def _build_column_map(self, headers: list[str]) -> dict[str, int | None]:
        """Build mapping from finding fields to column indices."""
        return {
            field: _find_column(headers, aliases)
            for field, aliases in _COLUMN_ALIASES.items()
        }

    def _row_to_finding(
        self,
        row: list[str],
        *,
        column_map: dict[str, int | None],
        row_number: int,
    ) -> Finding | None:
        """Convert one CSV row to a Finding.

        Args:
            row: CSV row values.
            column_map: Field-to-column-index mapping.
            row_number: 1-based row number for error reporting.

        Returns:
            Finding | None: Normalized finding or None if row lacks required data.
        """
        title = self._get_cell(row, column_map.get("title"))
        if not title:
            return None

        description = self._get_cell(row, column_map.get("description")) or title

        raw_severity = self._get_cell(row, column_map.get("severity")) or "info"
        severity = self._config.severity_map.resolve(
            raw_severity,
            tool_name=self._config.tool_name,
        )

        target = self._get_cell(row, column_map.get("target"))
        if not target:
            target = self._config.target_hint or "unknown"

        cwe = self._get_cell(row, column_map.get("cwe")) or None

        cvss: float | None = None
        cvss_str = self._get_cell(row, column_map.get("cvss"))
        if cvss_str:
            try:
                score = float(cvss_str)
                if 0.0 <= score <= 10.0:
                    cvss = score
            except (ValueError, TypeError):
                pass

        tool = self._get_cell(row, column_map.get("tool")) or self._config.tool_name

        # Preserve all columns as evidence.
        evidence: dict[str, Any] = {"csv_row": row_number}

        origin = self._build_origin(
            original_severity=raw_severity,
            line_number=row_number,
        )

        finding = Finding(
            title=title[:200],
            description=description,
            severity=severity,
            tool=tool,
            target=target,
            cwe=cwe,
            cvss=cvss,
            evidence=evidence,
        )
        return self._attach_origin(finding, origin)

    @staticmethod
    def _get_cell(row: list[str], index: int | None) -> str:
        """Safely extract a cell value from a CSV row.

        Args:
            row: CSV row.
            index: Column index.

        Returns:
            str: Stripped cell value or empty string.
        """
        if index is None or index >= len(row):
            return ""
        return row[index].strip()
