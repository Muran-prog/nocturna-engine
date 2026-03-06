"""Unit tests for in-memory JSONL text parser helper."""

from __future__ import annotations

from nocturna_engine.streaming.jsonl_engine import JsonlParserConfig
from nocturna_engine.streaming.jsonl_engine.parser import parse_jsonl_text


def test_parse_jsonl_text_parses_records_and_tracks_malformed_lines() -> None:
    """Helper should parse object lines and track malformed/non-object lines."""

    payload = "\n".join(
        [
            '{"id": 1}',
            "{bad json}",
            "[]",
            '{"id": 2}',
        ]
    )
    result = parse_jsonl_text(
        payload,
        config=JsonlParserConfig(max_line_bytes=1024, chunk_size=64),
    )

    assert result.payloads == [{"id": 1}, {"id": 2}]
    assert result.stats.total_lines == 4
    assert result.stats.parsed_lines == 2
    assert result.stats.malformed_lines == 2
    assert result.stats.skipped_lines == 2
    assert result.stats.oversized_lines == 0
    assert result.stats.emitted_records == 2


def test_parse_jsonl_text_tracks_oversized_lines() -> None:
    """Oversized line should be skipped while remaining records are parsed."""

    oversized = "x" * 512
    payload = f"{oversized}\n{{\"ok\": 1}}\n"
    result = parse_jsonl_text(
        payload,
        config=JsonlParserConfig(max_line_bytes=256, chunk_size=64),
    )

    assert result.payloads == [{"ok": 1}]
    assert result.stats.total_lines == 2
    assert result.stats.parsed_lines == 1
    assert result.stats.oversized_lines == 1
    assert result.stats.skipped_lines == 1


def test_parse_jsonl_text_handles_bytes_payload_without_trailing_newline() -> None:
    """EOF flush should parse final JSON object even without terminal newline."""

    result = parse_jsonl_text(
        b'{"id": 42}',
        config=JsonlParserConfig(max_line_bytes=1024, chunk_size=64),
    )

    assert result.payloads == [{"id": 42}]
    assert result.stats.total_lines == 1
    assert result.stats.parsed_lines == 1
    assert result.stats.malformed_lines == 0
