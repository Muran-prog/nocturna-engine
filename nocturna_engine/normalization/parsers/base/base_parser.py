"""Abstract base parser defining the contract for all normalization parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.errors import ParseError
from nocturna_engine.normalization.metadata import NormalizationOrigin, attach_normalization_origin
from nocturna_engine.normalization.parsers.base.parse_issue import ParseIssue
from nocturna_engine.normalization.parsers.base.parse_result import ParseResult
from nocturna_engine.normalization.parsers.base.parser_config import ParserConfig


class BaseParser(ABC):
    """Abstract base class for all normalization parsers.

    Parsers are stateless processors: they receive configuration at init time
    and produce findings from raw input. Each parser handles exactly one
    format family and can work in both batch and streaming modes.
    """

    parser_name: str = ""
    source_format: str = ""

    def __init__(
        self,
        config: ParserConfig,
        *,
        logger: BoundLogger | None = None,
    ) -> None:
        """Initialize parser with configuration.

        Args:
            config: Parser configuration.
            logger: Optional structured logger.
        """
        self._config = config
        self._logger = logger or structlog.get_logger(
            f"normalization.parser.{self.parser_name or self.__class__.__name__}"
        )

    @property
    def config(self) -> ParserConfig:
        """Return parser configuration."""
        return self._config

    @property
    def logger(self) -> BoundLogger:
        """Return parser-scoped logger."""
        return self._logger

    @abstractmethod
    async def parse(self, data: bytes | str) -> ParseResult:
        """Parse complete input data and return findings.

        This is the batch entry point for parsers. For large inputs,
        callers should use ``parse_stream`` instead.

        Args:
            data: Complete raw input from a security tool.

        Returns:
            ParseResult: Parsed findings, issues, and stats.
        """

    @abstractmethod
    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        """Parse streaming input data chunk-by-chunk.

        Parsers must handle partial data across chunks and produce
        findings incrementally. This method accumulates all findings
        into a single ParseResult.

        Args:
            stream: Async iterator of raw byte chunks.

        Returns:
            ParseResult: Accumulated findings, issues, and stats.
        """

    def _build_origin(
        self,
        *,
        original_severity: str | None = None,
        original_record: dict[str, Any] | None = None,
        line_number: int | None = None,
    ) -> NormalizationOrigin:
        """Build a NormalizationOrigin for a finding.

        Args:
            original_severity: Tool-native severity before mapping.
            original_record: Raw record if preservation is enabled.
            line_number: Source line number.

        Returns:
            NormalizationOrigin: Origin metadata.
        """
        return NormalizationOrigin(
            parser_name=self.parser_name,
            tool_name=self._config.tool_name,
            source_format=self.source_format,
            source_reference=self._config.source_reference,
            original_severity=original_severity,
            original_record=original_record if self._config.preserve_raw else None,
            line_number=line_number,
        )

    def _attach_origin(
        self,
        finding: Finding,
        origin: NormalizationOrigin,
    ) -> Finding:
        """Attach normalization origin to a finding's metadata.

        Creates a new Finding with updated metadata (Finding is validate_assignment).

        Args:
            finding: The finding to annotate.
            origin: Origin metadata.

        Returns:
            Finding: New finding with origin in metadata.
        """
        new_metadata = attach_normalization_origin(finding.metadata, origin)
        return finding.model_copy(update={"metadata": new_metadata})

    #: Maximum number of issues a single parse run may accumulate.
    _MAX_ISSUES: int = 10_000

    def _make_issue(
        self,
        message: str,
        *,
        line_number: int | None = None,
        raw_record: dict[str, Any] | None = None,
        error: Exception | None = None,
    ) -> ParseIssue:
        """Create a ParseIssue and log it.

        If the internal issue cap (``_MAX_ISSUES``) has been reached, the
        issue is still logged but an overflow sentinel is returned so callers
        can detect the situation without unbounded list growth.

        Args:
            message: Issue description.
            line_number: Source line number.
            raw_record: Raw record that caused the issue.
            error: Underlying exception.

        Returns:
            ParseIssue: The created issue.
        """
        self._logger.warning(
            "parse_issue",
            parser=self.parser_name,
            message=message,
            line_number=line_number,
            error=str(error) if error else None,
        )
        return ParseIssue(
            message=message,
            line_number=line_number,
            raw_record=raw_record,
            error=error,
        )
