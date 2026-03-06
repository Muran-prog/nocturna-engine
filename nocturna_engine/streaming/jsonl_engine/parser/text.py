"""Helpers for parsing in-memory JSONL payloads via the shared chunk parser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from structlog.stdlib import BoundLogger

from nocturna_engine.streaming.jsonl_engine.models import (
    JsonlIssueEnvelope,
    JsonlParserConfig,
    JsonlRecordEnvelope,
    JsonlStreamStats,
)
from nocturna_engine.streaming.jsonl_engine.parser.chunk_parser import JsonlChunkParser


@dataclass(slots=True)
class JsonlTextParseResult:
    """Parsed JSONL envelopes, issues, and counters for one in-memory payload."""

    records: list[JsonlRecordEnvelope]
    issues: list[JsonlIssueEnvelope]
    stats: JsonlStreamStats

    @property
    def payloads(self) -> list[dict[str, Any]]:
        """Return parsed JSON object payloads only."""

        return [record.payload for record in self.records]


def parse_jsonl_text(
    payload: str | bytes,
    *,
    config: JsonlParserConfig | None = None,
    logger: BoundLogger | None = None,
) -> JsonlTextParseResult:
    """Parse full JSONL text/bytes through the shared chunk parser path.

    Args:
        payload: Full JSONL payload in memory.
        config: Optional parser config overrides.
        logger: Optional structured logger override.

    Returns:
        JsonlTextParseResult: Parsed records/issues with aggregate stats.
    """

    active_config = config or JsonlParserConfig()
    parser = JsonlChunkParser(config=active_config, logger=logger)
    stats = JsonlStreamStats()
    records: list[JsonlRecordEnvelope] = []
    issues: list[JsonlIssueEnvelope] = []

    raw_payload = (
        payload
        if isinstance(payload, bytes)
        else str(payload).encode("utf-8", errors="replace")
    )
    chunk_size = max(1, int(active_config.chunk_size))

    for offset in range(0, len(raw_payload), chunk_size):
        batch = parser.feed(raw_payload[offset : offset + chunk_size], stats=stats)
        records.extend(batch.records)
        issues.extend(batch.issues)

    final_batch = parser.flush(stats=stats)
    records.extend(final_batch.records)
    issues.extend(final_batch.issues)
    stats.emitted_records = len(records)

    return JsonlTextParseResult(records=records, issues=issues, stats=stats)
