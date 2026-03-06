"""Regex-based plaintext parser for unstructured security tool output."""

from __future__ import annotations

import io
from collections.abc import AsyncIterator
from typing import Any

import structlog

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseParser, ParseResult, ParserConfig
from nocturna_engine.normalization.parsers.plaintext.patterns import (
    ExtractionPattern,
    _BUILTIN_PATTERNS,
)
from nocturna_engine.normalization.registry import register_parser

logger = structlog.get_logger("normalization.parser.plaintext")


@register_parser(
    name="plaintext",
    formats=[InputFormat.PLAINTEXT],
    tool_patterns=["masscan*", "zmap*", "dirb*", "gobuster*"],
    priority=1,
)
class PlaintextParser(BaseParser):
    """Regex-based parser for extracting findings from unstructured text output.

    Applies a list of extraction patterns to each line of input. Patterns
    are tried in order; the first match wins for each line. Users can
    provide additional patterns via the ``extra_patterns`` config key.
    """

    parser_name = "plaintext"
    source_format = "plaintext"

    def __init__(
        self,
        config: ParserConfig,
        *,
        logger: Any = None,
        extra_patterns: list[ExtractionPattern] | None = None,
    ) -> None:
        """Initialize with optional extra extraction patterns.

        Args:
            config: Parser configuration.
            logger: Optional structured logger.
            extra_patterns: Additional regex patterns to apply.
        """
        super().__init__(config, logger=logger)
        self._patterns = list(_BUILTIN_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete plaintext data.

        Args:
            data: Complete plaintext payload.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        stats = NormalizationStats()
        findings: list[Finding] = []
        issues = []

        for line_number, line in enumerate(io.StringIO(text), start=1):
            stripped = line.strip()
            if not stripped:
                continue

            stats.total_records_processed += 1
            finding = self._try_extract(stripped, line_number=line_number)
            if finding is not None:
                findings.append(finding)
                stats.findings_produced += 1
            else:
                stats.records_skipped += 1

        return ParseResult(findings=findings, issues=issues, stats=stats)

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse plaintext from a streaming byte source.

        Processes line-by-line as chunks arrive, handling partial lines
        across chunk boundaries.

        Args:
            stream: Async byte chunk iterator.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        stats = NormalizationStats()
        findings: list[Finding] = []
        issues = []
        partial_line = ""
        line_number = 0

        async for chunk in stream:
            text = chunk.decode("utf-8", errors="replace")
            text = partial_line + text
            lines = text.split("\n")

            # Last element may be incomplete — keep as partial.
            partial_line = lines[-1]

            for line in lines[:-1]:
                stripped = line.strip()
                if not stripped:
                    continue

                line_number += 1
                stats.total_records_processed += 1
                finding = self._try_extract(stripped, line_number=line_number)
                if finding is not None:
                    findings.append(finding)
                    stats.findings_produced += 1
                else:
                    stats.records_skipped += 1

        # Flush last partial line.
        if partial_line.strip():
            line_number += 1
            stats.total_records_processed += 1
            finding = self._try_extract(partial_line.strip(), line_number=line_number)
            if finding is not None:
                findings.append(finding)
                stats.findings_produced += 1
            else:
                stats.records_skipped += 1

        return ParseResult(findings=findings, issues=issues, stats=stats)

    def _try_extract(self, line: str, *, line_number: int) -> Finding | None:
        """Try each pattern against a line and return the first match.

        Args:
            line: Stripped text line.
            line_number: 1-based line number.

        Returns:
            Finding | None: Extracted finding or None.
        """
        for pattern in self._patterns:
            match = pattern.pattern.search(line)
            if match is None:
                continue

            groups = {k: (v or "") for k, v in match.groupdict().items()}

            # Determine severity.
            severity = pattern.severity
            if "severity" in groups:
                severity = self._config.severity_map.resolve(
                    groups["severity"],
                    tool_name=self._config.tool_name,
                )

            # Build title and description from templates.
            try:
                title = pattern.title_template.format(**groups).strip()
            except KeyError:
                title = line[:200]

            try:
                description = pattern.description_template.format(**groups).strip()
            except KeyError:
                description = line

            if not title:
                title = line[:200]
            if not description:
                description = title

            target = groups.get("host") or groups.get("url") or self._config.target_hint or "unknown"

            cwe: str | None = None
            cve = groups.get("cve")
            if cve:
                cwe = None  # CVE != CWE, but we capture it in evidence.

            evidence: dict[str, Any] = {
                "pattern_name": pattern.name,
                "raw_line": line[:1024],
                "line_number": line_number,
            }
            if cve:
                evidence["cve"] = cve

            origin = self._build_origin(
                line_number=line_number,
            )

            finding = Finding(
                title=title[:200],
                description=description,
                severity=severity,
                tool=self._config.tool_name,
                target=target,
                cwe=cwe,
                evidence=evidence,
            )
            return self._attach_origin(finding, origin)

        return None
