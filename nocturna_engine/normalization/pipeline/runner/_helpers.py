"""Internal helpers shared between batch and streaming normalization paths.

All functions here are private to the runner package — they are not part of
the public API and may change without notice.
"""

from __future__ import annotations

from time import perf_counter

import structlog

from nocturna_engine.normalization.detector import detect_format
from nocturna_engine.normalization.errors import FormatDetectionError, ParserNotFoundError
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseParser, ParseIssue, ParserConfig
from nocturna_engine.normalization.pipeline.config import NormalizationConfig
from nocturna_engine.normalization.pipeline.dedup import deduplicate_findings
from nocturna_engine.normalization.pipeline.result import NormalizationResult
from nocturna_engine.normalization.registry import ParserRegistry

logger = structlog.get_logger("normalization.pipeline")


# ---------------------------------------------------------------------------
# Error-result factory
# ---------------------------------------------------------------------------

def make_error_result(
    exc: Exception,
    start_time: float,
    *,
    detection: object | None = None,
    parser_name: str | None = None,
) -> NormalizationResult:
    """Build an aborted ``NormalizationResult`` from a caught exception."""
    return NormalizationResult(
        detection=detection,  # type: ignore[arg-type]
        parser_name=parser_name,
        issues=[ParseIssue(message=str(exc), error=exc)],
        stats=NormalizationStats(
            errors_encountered=1,
            duration_seconds=perf_counter() - start_time,
        ),
        aborted=True,
        abort_reason=str(exc),
    )


# ---------------------------------------------------------------------------
# Step 1: format detection
# ---------------------------------------------------------------------------

def detect(
    data: bytes | str,
    config: NormalizationConfig,
    start_time: float,
) -> tuple[object, NormalizationResult | None]:
    """Detect the input format.

    Returns:
        A ``(detection, error_result)`` tuple.  On success ``error_result``
        is ``None``.  On failure ``detection`` is ``None`` and
        ``error_result`` contains the aborted result.
    """
    try:
        detection = detect_format(
            data,
            format_hint=config.format_hint,
            tool_hint=config.tool_hint or config.tool_name,
        )
    except FormatDetectionError as exc:
        return None, make_error_result(exc, start_time)

    logger.info(
        "format_detected",
        format=detection.format.value,
        confidence=detection.confidence,
        method=detection.method,
        tool_hint=detection.tool_hint,
    )
    return detection, None


# ---------------------------------------------------------------------------
# Step 2: parser lookup
# ---------------------------------------------------------------------------

def lookup_parser(
    detection: object,
    config: NormalizationConfig,
    registry: ParserRegistry,
    start_time: float,
) -> tuple[type[BaseParser] | None, NormalizationResult | None]:
    """Look up a parser class for the detected format.

    Returns:
        ``(parser_class, error_result)`` — on success ``error_result`` is
        ``None``; on failure ``parser_class`` is ``None``.
    """
    try:
        parser_class = registry.lookup(
            detection.format,  # type: ignore[union-attr]
            tool_hint=detection.tool_hint or config.tool_hint,  # type: ignore[union-attr]
        )
    except ParserNotFoundError as exc:
        return None, make_error_result(exc, start_time, detection=detection)
    return parser_class, None


# ---------------------------------------------------------------------------
# Step 3: parser instantiation
# ---------------------------------------------------------------------------

def build_parser(
    parser_class: type[BaseParser],
    config: NormalizationConfig,
) -> BaseParser:
    """Instantiate a parser from its class and the normalization config."""
    parser_config = ParserConfig(
        tool_name=config.tool_name,
        target_hint=config.target_hint,
        severity_map=config.severity_map,
        preserve_raw=config.preserve_raw,
        source_reference=config.source_reference,
        extra=config.parser_options,
    )
    return parser_class(parser_config)


# ---------------------------------------------------------------------------
# Steps 4-6: post-parse processing (dedup, threshold check, result assembly)
# ---------------------------------------------------------------------------

def finalize(
    parse_result: object,
    detection: object,
    parser_name: str,
    config: NormalizationConfig,
    start_time: float,
) -> NormalizationResult:
    """Deduplicate findings, check error thresholds, and build the final result.

    This function covers the original pipeline steps 4-6.
    """
    findings = parse_result.findings  # type: ignore[union-attr]
    stats = parse_result.stats  # type: ignore[union-attr]

    # Step 4 & 5: Deduplicate.
    if config.deduplicate and findings:
        findings, merge_count = deduplicate_findings(findings)
        stats.duplicates_merged = merge_count

    # Step 6: Check error thresholds.
    aborted = False
    abort_reason = None
    if config.max_errors is not None and stats.errors_encountered >= config.max_errors:
        aborted = True
        abort_reason = (
            f"Error count {stats.errors_encountered} exceeded "
            f"threshold {config.max_errors}."
        )
    if (
        config.max_error_rate is not None
        and stats.total_records_processed > 0
        and stats.error_rate > config.max_error_rate
    ):
        aborted = True
        abort_reason = (
            f"Error rate {stats.error_rate:.4f} exceeded "
            f"threshold {config.max_error_rate:.4f}."
        )

    stats.duration_seconds = perf_counter() - start_time

    logger.info(
        "normalization_complete",
        parser=parser_name,
        findings=stats.findings_produced,
        errors=stats.errors_encountered,
        duplicates_merged=stats.duplicates_merged,
        duration_seconds=round(stats.duration_seconds, 4),
        aborted=aborted,
    )

    return NormalizationResult(
        findings=findings,
        issues=parse_result.issues,  # type: ignore[union-attr]
        stats=stats,
        detection=detection,  # type: ignore[arg-type]
        parser_name=parser_name,
        aborted=aborted,
        abort_reason=abort_reason,
    )
