"""Batch model for chunk parser outputs."""

from __future__ import annotations

from dataclasses import dataclass

from nocturna_engine.streaming.jsonl_engine.models import JsonlIssueEnvelope, JsonlRecordEnvelope


@dataclass(slots=True)
class ParserBatch:
    """One parser output batch with parsed records and non-fatal issues."""

    records: list[JsonlRecordEnvelope]
    issues: list[JsonlIssueEnvelope]
