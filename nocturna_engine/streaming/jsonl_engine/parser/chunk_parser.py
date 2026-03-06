"""Chunk-aware JSONL parser with line-size guards and issue reporting."""

from __future__ import annotations

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.models import (
    JsonlIssueEnvelope,
    JsonlParserConfig,
    JsonlRecordEnvelope,
    JsonlStreamStats,
)
from nocturna_engine.streaming.jsonl_engine.parser.batch import ParserBatch
from nocturna_engine.streaming.jsonl_engine.parser.line_handling import JsonlLineHandlingMixin


class JsonlChunkParser(JsonlLineHandlingMixin):
    """Parses chunked stdout into JSONL records with bounded line assembly."""

    def __init__(
        self,
        *,
        config: JsonlParserConfig,
        logger: BoundLogger | None = None,
    ) -> None:
        """Initialize parser state.

        Args:
            config: Parser configuration.
            logger: Optional structured logger.
        """

        self._config = config
        self._logger = logger or structlog.get_logger("jsonl_chunk_parser")
        self._partial_line = bytearray()
        self._line_number = 0
        self._discard_until_newline = False

    def feed(self, chunk: bytes, *, stats: JsonlStreamStats) -> ParserBatch:
        """Consume one stdout chunk and emit parsed records/issues.

        Args:
            chunk: Raw process stdout chunk.
            stats: Mutable stats counters.

        Returns:
            ParserBatch: Parsed records and issues emitted by this chunk.
        """

        records: list[JsonlRecordEnvelope] = []
        issues: list[JsonlIssueEnvelope] = []
        if not chunk:
            return ParserBatch(records=records, issues=issues)

        cursor = 0
        while cursor < len(chunk):
            if self._discard_until_newline:
                newline_index = chunk.find(b"\n", cursor)
                if newline_index == -1:
                    return ParserBatch(records=records, issues=issues)
                cursor = newline_index + 1
                self._discard_until_newline = False
                issues.append(self._register_oversized_issue(stats))
                continue

            newline_index = chunk.find(b"\n", cursor)
            if newline_index == -1:
                tail = chunk[cursor:]
                if len(self._partial_line) + len(tail) > self._config.max_line_bytes:
                    self._partial_line.clear()
                    self._discard_until_newline = True
                else:
                    self._partial_line.extend(tail)
                break

            segment = chunk[cursor : newline_index + 1]
            cursor = newline_index + 1

            if len(self._partial_line) + len(segment) > self._config.max_line_bytes:
                self._partial_line.clear()
                issues.append(self._register_oversized_issue(stats))
                continue

            self._partial_line.extend(segment)
            record, issue = self._parse_ready_line(stats)
            if record is not None:
                records.append(record)
            if issue is not None:
                issues.append(issue)

        return ParserBatch(records=records, issues=issues)

    def flush(self, *, stats: JsonlStreamStats) -> ParserBatch:
        """Flush remaining parser buffers at EOF.

        Args:
            stats: Mutable stats counters.

        Returns:
            ParserBatch: Parsed records and issues from final buffered data.
        """

        records: list[JsonlRecordEnvelope] = []
        issues: list[JsonlIssueEnvelope] = []

        if self._discard_until_newline:
            self._discard_until_newline = False
            issues.append(self._register_oversized_issue(stats))

        if self._partial_line:
            record, issue = self._parse_ready_line(stats, eof=True)
            if record is not None:
                records.append(record)
            if issue is not None:
                issues.append(issue)

        return ParserBatch(records=records, issues=issues)
