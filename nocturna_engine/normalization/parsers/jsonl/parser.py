"""JSONL parser integrating with the existing jsonl_engine streaming infrastructure."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import structlog

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseParser, ParseResult, ParserConfig
from nocturna_engine.normalization.parsers.json_generic import GenericJsonParser
from nocturna_engine.normalization.parsers.jsonl.batch_processing import process_batch
from nocturna_engine.normalization.registry import register_parser
from nocturna_engine.streaming.jsonl_engine.models import JsonlParserConfig, JsonlStreamStats
from nocturna_engine.streaming.jsonl_engine.parser.chunk_parser import JsonlChunkParser

logger = structlog.get_logger("normalization.parser.jsonl")


@register_parser(
    name="jsonl",
    formats=[InputFormat.JSONL],
    tool_patterns=["nuclei*", "subfinder*", "httpx*", "katana*", "ffuf*"],
    priority=10,
)
class JsonlNormalizationParser(BaseParser):
    """JSONL (newline-delimited JSON) parser using the jsonl_engine chunk parser.

    Integrates with the existing ``nocturna_engine.streaming.jsonl_engine``
    infrastructure for chunk-aware, memory-bounded line parsing. Each parsed
    JSON object is then normalized through the same field mapping logic as
    the generic JSON parser.
    """

    parser_name = "jsonl"
    source_format = "jsonl"

    def __init__(
        self,
        config: ParserConfig,
        *,
        logger: Any = None,
        max_line_bytes: int = 1024 * 1024,
        chunk_size: int = 8192,
    ) -> None:
        """Initialize JSONL parser with streaming configuration.

        Args:
            config: Parser configuration.
            logger: Optional structured logger.
            max_line_bytes: Maximum bytes per JSONL line.
            chunk_size: Chunk size for stream processing.
        """
        super().__init__(config, logger=logger)
        self._parser_config = JsonlParserConfig(
            max_line_bytes=max_line_bytes,
            chunk_size=chunk_size,
        )
        # Delegate per-record conversion to GenericJsonParser logic.
        self._json_parser = GenericJsonParser(config, logger=self._logger)

    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete JSONL data.

        Args:
            data: Complete JSONL payload.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        stats = NormalizationStats()

        chunk_parser = JsonlChunkParser(
            config=self._parser_config,
            logger=self._logger,
        )
        stream_stats = JsonlStreamStats()

        # Feed data through chunk parser.
        findings: list[Finding] = []
        issues = []

        chunk_size = max(1, self._parser_config.chunk_size)
        for offset in range(0, len(raw_bytes), chunk_size):
            batch = chunk_parser.feed(
                raw_bytes[offset:offset + chunk_size],
                stats=stream_stats,
            )
            process_batch(
                batch,
                findings=findings,
                issues=issues,
                stats=stats,
                record_to_finding=self._record_to_finding,
                make_issue=self._make_issue,
            )

        # Flush remaining buffered data.
        final_batch = chunk_parser.flush(stats=stream_stats)
        process_batch(
            final_batch,
            findings=findings,
            issues=issues,
            stats=stats,
            record_to_finding=self._record_to_finding,
            make_issue=self._make_issue,
        )

        return ParseResult(findings=findings, issues=issues, stats=stats)

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse JSONL from a streaming byte source.

        Uses the jsonl_engine chunk parser for memory-bounded streaming.

        Args:
            stream: Async byte chunk iterator.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        stats = NormalizationStats()
        chunk_parser = JsonlChunkParser(
            config=self._parser_config,
            logger=self._logger,
        )
        stream_stats = JsonlStreamStats()

        findings: list[Finding] = []
        issues = []

        async for chunk in stream:
            batch = chunk_parser.feed(chunk, stats=stream_stats)
            process_batch(
                batch,
                findings=findings,
                issues=issues,
                stats=stats,
                record_to_finding=self._record_to_finding,
                make_issue=self._make_issue,
            )

        # Flush.
        final_batch = chunk_parser.flush(stats=stream_stats)
        process_batch(
            final_batch,
            findings=findings,
            issues=issues,
            stats=stats,
            record_to_finding=self._record_to_finding,
            make_issue=self._make_issue,
        )

        return ParseResult(findings=findings, issues=issues, stats=stats)

    def _record_to_finding(
        self,
        record: dict[str, Any],
        *,
        line_number: int | None = None,
    ) -> Finding | None:
        """Delegate per-record conversion to GenericJsonParser logic.

        Args:
            record: Parsed JSON object from JSONL line.
            line_number: Source line number.

        Returns:
            Finding | None: Normalized finding, or None if record is not a finding.
        """
        result = self._json_parser._record_to_finding(record, index=line_number or 0)
        if result is not None and line_number is not None:
            # Re-attach origin with line number.
            origin = self._build_origin(
                original_record=record if self._config.preserve_raw else None,
                line_number=line_number,
            )
            result = self._attach_origin(result, origin)
        return result
