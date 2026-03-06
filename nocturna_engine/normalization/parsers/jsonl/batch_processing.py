"""Batch processing helpers for JSONL parser.

Extracts issues and converts records from chunk parser batches
into findings. Used by both ``parse`` and ``parse_stream`` code paths
to avoid duplication.
"""

from __future__ import annotations

from typing import Any

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.streaming.jsonl_engine.parser.batch import ParserBatch

# ---------------------------------------------------------------------------
# Type alias for the record→finding converter callback used by the parser.
# ---------------------------------------------------------------------------
RecordToFindingFn = Any  # Callable[[dict, *, int|None], Finding|None]

# ---------------------------------------------------------------------------
# Type alias for the _make_issue callback used by the parser.
# ---------------------------------------------------------------------------
MakeIssueFn = Any  # Callable[..., ParseIssue]


def collect_issues(
    batch: ParserBatch,
    *,
    issues: list[ParseIssue],
    stats: NormalizationStats,
    make_issue: MakeIssueFn,
) -> None:
    """Collect issues from a chunk parser batch into *issues* list.

    Args:
        batch: Parsed batch from ``JsonlChunkParser.feed`` / ``flush``.
        issues: Accumulator list of parse issues.
        stats: Normalization statistics to update.
        make_issue: Callback to create a ``ParseIssue`` from error info.
    """
    for issue_envelope in batch.issues:
        issues.append(make_issue(
            str(issue_envelope.error),
            line_number=issue_envelope.line_number,
            error=issue_envelope.error,
        ))
        stats.errors_encountered += 1


def collect_findings(
    batch: ParserBatch,
    *,
    findings: list[Finding],
    issues: list[ParseIssue],
    stats: NormalizationStats,
    record_to_finding: RecordToFindingFn,
    make_issue: MakeIssueFn,
) -> None:
    """Convert records from a chunk parser batch into findings.

    Args:
        batch: Parsed batch from ``JsonlChunkParser.feed`` / ``flush``.
        findings: Accumulator list of produced findings.
        issues: Accumulator list of parse issues.
        stats: Normalization statistics to update.
        record_to_finding: Callback converting a single JSON record to a
            ``Finding`` (or ``None`` to skip).
        make_issue: Callback to create a ``ParseIssue`` from error info.
    """
    for record_envelope in batch.records:
        stats.total_records_processed += 1
        try:
            finding = record_to_finding(
                record_envelope.payload,
                line_number=record_envelope.line_number,
            )
            if finding is not None:
                findings.append(finding)
                stats.findings_produced += 1
            else:
                stats.records_skipped += 1
        except Exception as exc:
            stats.errors_encountered += 1
            issues.append(make_issue(
                f"Failed to convert record at line {record_envelope.line_number}: {exc}",
                line_number=record_envelope.line_number,
                raw_record=record_envelope.payload,
                error=exc,
            ))


def process_batch(
    batch: ParserBatch,
    *,
    findings: list[Finding],
    issues: list[ParseIssue],
    stats: NormalizationStats,
    record_to_finding: RecordToFindingFn,
    make_issue: MakeIssueFn,
) -> None:
    """Process a full chunk parser batch — issues first, then records.

    Convenience wrapper combining :func:`collect_issues` and
    :func:`collect_findings`.

    Args:
        batch: Parsed batch from ``JsonlChunkParser.feed`` / ``flush``.
        findings: Accumulator list of produced findings.
        issues: Accumulator list of parse issues.
        stats: Normalization statistics to update.
        record_to_finding: Callback converting a single JSON record to a
            ``Finding`` (or ``None`` to skip).
        make_issue: Callback to create a ``ParseIssue`` from error info.
    """
    collect_issues(batch, issues=issues, stats=stats, make_issue=make_issue)
    collect_findings(
        batch,
        findings=findings,
        issues=issues,
        stats=stats,
        record_to_finding=record_to_finding,
        make_issue=make_issue,
    )
