"""HTML parser for security tool reports (Nikto, ZAP, Burp, generic tables)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import structlog

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.errors import ParseError
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseParser, ParseResult
from nocturna_engine.normalization.parsers.html._table_extractor import (
    _HtmlTableHandler,
)
from nocturna_engine.normalization.parsers.html.fallback import extract_cve_findings
from nocturna_engine.normalization.parsers.html.parser._table_conversion import (
    _TableConversionMixin,
)
from nocturna_engine.normalization.registry import register_parser

logger = structlog.get_logger("normalization.parser.html")


@register_parser(
    name="html",
    formats=[InputFormat.HTML],
    tool_patterns=["nikto*", "zap*", "burp*", "arachni*", "wapiti*"],
    priority=5,
)
class HtmlParser(_TableConversionMixin, BaseParser):
    """Parser for HTML security tool reports.

    Supports two extraction modes:

    1. **Table extraction** — finds ``<table>`` elements with security-related
       headers (vulnerability, severity, risk, host, etc.) and maps columns
       using the same alias set as the CSV generic parser.

    2. **Text fallback** — if no qualifying tables are found, scans all
       visible text for CVE identifiers and creates findings from those.
    """

    parser_name = "html"
    source_format = "html"

    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete HTML data.

        Args:
            data: Complete HTML payload.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        stats = NormalizationStats()

        handler = _HtmlTableHandler()
        handler.feed(text)
        handler.close()

        findings: list[Finding] = []
        issues = []

        if handler.tables:
            # Table extraction mode.
            for table_index, table in enumerate(handler.tables):
                table_findings, table_issues = self._extract_from_table(
                    table,
                    table_index=table_index,
                    stats=stats,
                )
                findings.extend(table_findings)
                issues.extend(table_issues)
        else:
            # Fallback: extract CVE patterns from visible text.
            target = self._config.target_hint or "unknown"
            fallback_findings = extract_cve_findings(
                handler.all_text_chunks,
                tool_name=self._config.tool_name,
                target_hint=target,
            )
            for finding in fallback_findings:
                stats.total_records_processed += 1
                origin = self._build_origin(
                    original_severity=finding.severity.value,
                )
                finding = self._attach_origin(finding, origin)
                findings.append(finding)
                stats.findings_produced += 1

            if not fallback_findings:
                logger.info(
                    "html_no_findings",
                    parser=self.parser_name,
                    reason="No security tables or CVE patterns found in HTML.",
                )

        stats.records_skipped = (
            stats.total_records_processed - stats.findings_produced - stats.errors_encountered
        )
        return ParseResult(findings=findings, issues=issues, stats=stats)

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse HTML from a streaming byte source.

        HTML cannot be parsed incrementally (table headers must be known
        before data rows can be mapped), so this method accumulates all
        chunks and delegates to :meth:`parse`.

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
                    f"HTML input exceeds maximum allowed size ({max_bytes} bytes).",
                    source_parser=self.parser_name,
                )
            chunks.append(chunk)
        full_data = b"".join(chunks)
        return await self.parse(full_data)
