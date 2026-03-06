"""Exception hierarchy for the Universal Finding Normalization subsystem."""

from __future__ import annotations

from typing import Any

from nocturna_engine.exceptions import NocturnaError


class NormalizationError(NocturnaError):
    """Base exception for all normalization failures."""

    default_code = "normalization_error"
    default_category = "normalization"


class FormatDetectionError(NormalizationError):
    """Raised when input format cannot be determined."""

    default_code = "format_detection_error"
    default_category = "normalization_detection"
    default_remediation = "Provide an explicit format_hint or verify input data is valid."


class ParserNotFoundError(NormalizationError):
    """Raised when no registered parser supports the detected format."""

    default_code = "parser_not_found"
    default_category = "normalization_registry"
    default_remediation = "Register a parser for this format or provide a format_hint."


class ParserRegistrationError(NormalizationError):
    """Raised when a parser fails to register (duplicate name, invalid class)."""

    default_code = "parser_registration_error"
    default_category = "normalization_registry"
    default_remediation = "Fix parser class metadata and register again."


class ParseError(NormalizationError):
    """Raised when a parser encounters an unrecoverable error."""

    default_code = "parse_error"
    default_category = "normalization_parsing"
    default_retryable = False

    def __init__(
        self,
        message: str | None = None,
        *,
        line_number: int | None = None,
        source_parser: str | None = None,
        code: str | None = None,
        category: str | None = None,
        retryable: bool | None = None,
        remediation: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize parse error with optional location metadata.

        Args:
            message: Human-readable error description.
            line_number: 1-based line number in source where error occurred.
            source_parser: Name of the parser that raised this error.
            code: Error code override.
            category: Error category override.
            retryable: Whether this error is retryable.
            remediation: Remediation guidance.
            context: Additional structured context.
        """
        merged_context = dict(context or {})
        if line_number is not None:
            merged_context["line_number"] = line_number
        if source_parser is not None:
            merged_context["source_parser"] = source_parser

        super().__init__(
            message,
            code=code,
            category=category,
            retryable=retryable,
            remediation=remediation,
            context=merged_context,
        )
        self.line_number = line_number
        self.source_parser = source_parser


class SeverityMappingError(NormalizationError):
    """Raised when a severity value cannot be mapped to SeverityLevel."""

    default_code = "severity_mapping_error"
    default_category = "normalization_severity"
    default_remediation = "Add a severity mapping for this tool/value combination."


class StreamExhaustedError(NormalizationError):
    """Raised when a stream source is unexpectedly closed or exhausted."""

    default_code = "stream_exhausted"
    default_category = "normalization_streaming"
    default_retryable = True
    default_remediation = "Verify the input stream is complete and retry."
