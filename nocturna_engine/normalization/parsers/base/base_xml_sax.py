"""Base classes for SAX-based XML parsers and their content handlers.

Provides:
- ``BaseNocturnaContentHandler``: SAX handler with shared init, characters(),
  and _emit_finding() helper that encapsulates the try/except/stats/issues
  boilerplate common to all XML-based normalization handlers.
- ``BaseXmlSaxParser``: Parser with defusedxml-backed parse() / parse_stream()
  that delegates handler construction to subclasses via _create_sax_handler().
"""

from __future__ import annotations

import xml.sax
import xml.sax.handler
from abc import abstractmethod
from collections.abc import AsyncIterator, Callable
from io import BytesIO
from typing import Any

from defusedxml import sax as defused_sax

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.metadata import (
    NormalizationStats,
    attach_normalization_origin,
)
from nocturna_engine.normalization.parsers.base.base_parser import BaseParser
from nocturna_engine.normalization.parsers.base.parse_issue import ParseIssue
from nocturna_engine.normalization.parsers.base.parse_result import ParseResult
from nocturna_engine.normalization.parsers.base.parser_config import ParserConfig
from nocturna_engine.normalization.severity import SeverityMap


# ---------------------------------------------------------------------------
# Base SAX content handler
# ---------------------------------------------------------------------------


class BaseNocturnaContentHandler(xml.sax.handler.ContentHandler):
    """Base SAX handler with common init, character buffering and emit helpers.

    Subclasses must implement ``startElement`` and ``endElement`` with their
    domain-specific parsing logic.  They should call ``_emit_finding`` inside
    ``endElement`` to convert parsed data into :class:`Finding` objects with
    unified error handling and stats tracking.
    """

    def __init__(
        self,
        *,
        config: ParserConfig,
        stats: NormalizationStats,
        severity_map: SeverityMap | Any,
        preserve_raw: bool,
    ) -> None:
        super().__init__()
        self._config = config
        self._stats = stats
        self._severity_map = severity_map
        self._preserve_raw = preserve_raw
        self.findings: list[Finding] = []
        self.issues: list[ParseIssue] = []
        self._char_buffer: list[str] = []

    # -- SAX callback --------------------------------------------------------

    def characters(self, content: str) -> None:  # noqa: D401
        """Buffer character data between element boundaries."""
        self._char_buffer.append(content)

    # -- Helpers -------------------------------------------------------------

    def _emit_finding(
        self,
        converter_callable: Callable[[], Finding | None],
        *,
        error_context: str = "",
    ) -> None:
        """Call *converter_callable* and append the result to findings.

        Encapsulates the recurring try / except / stats / issues pattern used
        across all XML SAX handlers.

        Args:
            converter_callable: Zero-arg callable that returns a Finding or
                None (skipped record).
            error_context: Human-readable label included in the ParseIssue
                message on failure (e.g. ``"Nessus item"``).
        """
        self._stats.total_records_processed += 1
        try:
            finding = converter_callable()
            if finding is not None:
                self.findings.append(finding)
                self._stats.findings_produced += 1
            else:
                self._stats.records_skipped += 1
        except Exception as exc:
            self._stats.errors_encountered += 1
            ctx = f" {error_context}" if error_context else ""
            self.issues.append(ParseIssue(
                message=f"Failed to convert{ctx}: {exc}",
                error=exc,
            ))

    @staticmethod
    def _attach_origin_safe(finding: Finding, origin: Any) -> Finding:
        """Attach normalization origin with a defensive metadata copy.

        Always copies ``finding.metadata`` before mutation so that the
        original Finding object is never modified in-place.
        """
        metadata = finding.metadata.copy()
        metadata = attach_normalization_origin(metadata, origin)
        return finding.model_copy(update={"metadata": metadata})


# ---------------------------------------------------------------------------
# Base XML SAX parser
# ---------------------------------------------------------------------------


class BaseXmlSaxParser(BaseParser):
    """Abstract XML parser that wires defusedxml SAX to a handler subclass.

    Concrete parsers only need to implement ``_create_sax_handler`` (and
    optionally ``_pre_parse`` for pre-validation).  ``parse()`` and
    ``parse_stream()`` are fully provided by this base class.
    """

    @abstractmethod
    def _create_sax_handler(
        self,
        *,
        config: ParserConfig,
        stats: NormalizationStats,
        severity_map: SeverityMap | Any,
        preserve_raw: bool,
    ) -> xml.sax.handler.ContentHandler:
        """Create the domain-specific SAX handler.

        Returns:
            A ContentHandler (typically a BaseNocturnaContentHandler subclass)
            whose ``findings`` and ``issues`` attributes will be read after
            parsing completes.
        """

    def _pre_parse(self, data: bytes, stats: NormalizationStats) -> bytes:
        """Hook for pre-validation before SAX parsing.

        The default implementation returns *data* unchanged.  Parsers that
        need to validate or transform the raw bytes (e.g. JUnit pre-checks)
        should override this method.

        Args:
            data: Raw bytes (already encoded).
            stats: Stats object for recording pre-parse issues.

        Returns:
            Bytes to feed into the SAX parser.
        """
        return data

    # -- Public API (final) --------------------------------------------------

    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete XML data via defusedxml SAX.

        Args:
            data: Complete XML payload.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        stats = NormalizationStats()

        raw_bytes = self._pre_parse(raw_bytes, stats)

        handler = self._create_sax_handler(
            config=self._config,
            stats=stats,
            severity_map=self._config.severity_map,
            preserve_raw=self._config.preserve_raw,
        )

        try:
            defused_sax.parse(BytesIO(raw_bytes), handler)
        except xml.sax.SAXParseException as exc:
            handler.issues.append(ParseIssue(
                message=f"XML parse error: {exc}",
                line_number=exc.getLineNumber(),
                error=exc,
            ))
            stats.errors_encountered += 1

        return ParseResult(
            findings=handler.findings,
            issues=handler.issues,
            stats=stats,
        )

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse XML from a streaming byte source via defusedxml SAX.

        Uses defusedxml's incremental SAX parser for streaming, providing
        the same XXE and entity expansion protection as the parse() method.

        Args:
            stream: Async byte chunk iterator.

        Returns:
            ParseResult: Parsed findings and issues.
        """
        stats = NormalizationStats()

        handler = self._create_sax_handler(
            config=self._config,
            stats=stats,
            severity_map=self._config.severity_map,
            preserve_raw=self._config.preserve_raw,
        )

        # Use defusedxml's incremental SAX parser for streaming.
        parser = defused_sax.make_parser()
        parser.setContentHandler(handler)

        try:
            async for chunk in stream:
                parser.feed(chunk)
            parser.close()
        except xml.sax.SAXParseException as exc:
            handler.issues.append(ParseIssue(
                message=f"XML stream parse error: {exc}",
                line_number=exc.getLineNumber(),
                error=exc,
            ))
            stats.errors_encountered += 1

        return ParseResult(
            findings=handler.findings,
            issues=handler.issues,
            stats=stats,
        )
