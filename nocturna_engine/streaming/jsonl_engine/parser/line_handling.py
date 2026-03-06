"""Line parsing and issue helpers for the chunk-aware JSONL parser."""

from __future__ import annotations

import json

from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.errors import JsonlLineTooLongError, JsonlMalformedLineError
from nocturna_engine.streaming.jsonl_engine.models import (
    JsonlIssueEnvelope,
    JsonlParserConfig,
    JsonlRecordEnvelope,
    JsonlStreamStats,
)
from nocturna_engine.streaming.jsonl_engine.utils import truncate_text


class JsonlLineHandlingMixin:
    """Internal helpers for line-level parsing and issue normalization."""

    _config: JsonlParserConfig
    _logger: BoundLogger
    _partial_line: bytearray
    _line_number: int

    def _parse_ready_line(
        self,
        stats: JsonlStreamStats,
        *,
        eof: bool = False,
    ) -> tuple[JsonlRecordEnvelope | None, JsonlIssueEnvelope | None]:
        """Parse one completed line from internal buffer.

        Args:
            stats: Mutable stats counters.
            eof: Whether this line is emitted during EOF flush.

        Returns:
            tuple[JsonlRecordEnvelope | None, JsonlIssueEnvelope | None]:
                Parsed record or issue.
        """

        line_bytes = bytes(self._partial_line)
        self._partial_line.clear()

        if not eof and not line_bytes.endswith(b"\n"):
            self._partial_line.extend(line_bytes)
            return None, None

        self._line_number += 1
        stats.total_lines += 1

        text_line = line_bytes.decode("utf-8", errors="replace").strip()
        if not text_line:
            return None, None

        try:
            payload = json.loads(text_line)
        except json.JSONDecodeError as exc:
            stats.malformed_lines += 1
            stats.skipped_lines += 1
            error = JsonlMalformedLineError(
                line_number=self._line_number,
                reason=str(exc),
            )
            self._logger.warning(
                "jsonl_line_malformed",
                line_number=self._line_number,
                error=str(exc),
            )
            return None, self._build_issue(
                line_number=self._line_number,
                raw_line=text_line,
                error=error,
            )

        if not isinstance(payload, dict):
            stats.malformed_lines += 1
            stats.skipped_lines += 1
            payload_type = type(payload).__name__
            error = JsonlMalformedLineError(
                line_number=self._line_number,
                reason=f"JSON value type '{payload_type}' is not an object.",
            )
            self._logger.warning(
                "jsonl_line_not_object",
                line_number=self._line_number,
                payload_type=payload_type,
            )
            return None, self._build_issue(
                line_number=self._line_number,
                raw_line=text_line,
                error=error,
            )

        stats.parsed_lines += 1
        return (
            JsonlRecordEnvelope(
                line_number=self._line_number,
                raw_line=truncate_text(text_line, max_chars=self._config.max_issue_line_chars),
                payload=payload,
            ),
            None,
        )

    def _register_oversized_issue(self, stats: JsonlStreamStats) -> JsonlIssueEnvelope:
        """Register oversized-line issue and update stats.

        Args:
            stats: Mutable stats counters.

        Returns:
            JsonlIssueEnvelope: Oversized line issue payload.
        """

        self._line_number += 1
        stats.total_lines += 1
        stats.oversized_lines += 1
        stats.skipped_lines += 1

        error = JsonlLineTooLongError(
            line_number=self._line_number,
            max_line_bytes=self._config.max_line_bytes,
        )
        self._logger.warning(
            "jsonl_line_oversized",
            line_number=self._line_number,
            max_line_bytes=self._config.max_line_bytes,
        )
        return self._build_issue(line_number=self._line_number, raw_line=None, error=error)

    def _build_issue(
        self,
        *,
        line_number: int | None,
        raw_line: str | None,
        error: Exception,
    ) -> JsonlIssueEnvelope:
        """Build normalized issue envelope.

        Args:
            line_number: 1-based line number, when available.
            raw_line: Optional raw line snapshot.
            error: Issue exception.

        Returns:
            JsonlIssueEnvelope: Issue payload.
        """

        safe_line = None
        if raw_line is not None:
            safe_line = truncate_text(raw_line, max_chars=self._config.max_issue_line_chars)
        return JsonlIssueEnvelope(
            line_number=line_number,
            raw_line=safe_line,
            error=error,
            source="stdout",
        )
