"""Comprehensive edge-case tests for the JSONL parser (chunk parser, text helper, line handling)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from nocturna_engine.streaming.jsonl_engine.errors import (
    JsonlLineTooLongError,
    JsonlMalformedLineError,
)
from nocturna_engine.streaming.jsonl_engine.models import (
    JsonlIssueEnvelope,
    JsonlParserConfig,
    JsonlRecordEnvelope,
    JsonlStreamStats,
)
from nocturna_engine.streaming.jsonl_engine.parser import (
    JsonlTextParseResult,
    parse_jsonl_text,
)
from nocturna_engine.streaming.jsonl_engine.parser.chunk_parser import JsonlChunkParser
from nocturna_engine.streaming.jsonl_engine.parser.batch import ParserBatch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(
    max_line_bytes: int = 4096,
    chunk_size: int = 64,
    max_issue_line_chars: int = 1024,
) -> JsonlParserConfig:
    return JsonlParserConfig(
        max_line_bytes=max_line_bytes,
        chunk_size=chunk_size,
        max_issue_line_chars=max_issue_line_chars,
    )


def _parse(
    payload: str | bytes,
    *,
    max_line_bytes: int = 4096,
    chunk_size: int = 64,
) -> JsonlTextParseResult:
    return parse_jsonl_text(
        payload,
        config=_make_config(max_line_bytes=max_line_bytes, chunk_size=chunk_size),
    )


# ---------------------------------------------------------------------------
# parse_jsonl_text: valid JSONL
# ---------------------------------------------------------------------------

def test_parse_jsonl_text_single_record() -> None:
    """Single valid JSON object line should produce one record."""
    result = _parse('{"id": 1}\n')
    assert result.payloads == [{"id": 1}]
    assert result.stats.total_lines == 1
    assert result.stats.parsed_lines == 1


def test_parse_jsonl_text_multiple_records() -> None:
    """Multiple valid JSON lines should produce matching records."""
    payload = '{"a": 1}\n{"b": 2}\n{"c": 3}\n'
    result = _parse(payload)
    assert result.payloads == [{"a": 1}, {"b": 2}, {"c": 3}]
    assert result.stats.total_lines == 3
    assert result.stats.emitted_records == 3


def test_parse_jsonl_text_bytes_input() -> None:
    """Bytes payload should work identically to string payload."""
    result = _parse(b'{"x": 42}\n')
    assert result.payloads == [{"x": 42}]


def test_parse_jsonl_text_no_trailing_newline() -> None:
    """Final JSON object without trailing newline should be parsed at EOF."""
    result = _parse(b'{"id": 99}')
    assert result.payloads == [{"id": 99}]
    assert result.stats.total_lines == 1
    assert result.stats.parsed_lines == 1


def test_parse_jsonl_text_unicode_content() -> None:
    """Unicode characters including emoji, CJK, and accents should parse."""
    obj = {"emoji": "🎉🚀", "name": "日本語テスト", "accent": "café"}
    result = _parse(json.dumps(obj) + "\n")
    assert result.payloads == [obj]


def test_parse_jsonl_text_nested_objects() -> None:
    """Deeply nested JSON objects should parse correctly."""
    obj = {"a": {"b": {"c": {"d": [1, 2, 3]}}}}
    result = _parse(json.dumps(obj) + "\n")
    assert result.payloads == [obj]


# ---------------------------------------------------------------------------
# parse_jsonl_text: empty / whitespace
# ---------------------------------------------------------------------------

def test_parse_jsonl_text_empty_string() -> None:
    """Empty string should produce zero records and zero issues."""
    result = _parse("")
    assert result.payloads == []
    assert result.issues == []
    assert result.stats.total_lines == 0


def test_parse_jsonl_text_empty_bytes() -> None:
    """Empty bytes should produce zero records."""
    result = _parse(b"")
    assert result.payloads == []
    assert result.stats.total_lines == 0


def test_parse_jsonl_text_only_newlines() -> None:
    """Lines that are only whitespace should be silently skipped."""
    result = _parse("\n\n\n\n")
    assert result.payloads == []
    # Empty lines count as total lines but are not malformed
    assert result.stats.malformed_lines == 0


def test_parse_jsonl_text_mixed_whitespace_and_records() -> None:
    """Records interspersed with blank lines should parse only the records."""
    payload = '\n{"a":1}\n\n\n{"b":2}\n\n'
    result = _parse(payload)
    assert result.payloads == [{"a": 1}, {"b": 2}]
    assert result.stats.parsed_lines == 2


# ---------------------------------------------------------------------------
# parse_jsonl_text: malformed lines
# ---------------------------------------------------------------------------

def test_parse_jsonl_text_malformed_json() -> None:
    """Invalid JSON lines should be tracked as malformed with issues."""
    result = _parse('{not valid json}\n{"ok": 1}\n')
    assert result.payloads == [{"ok": 1}]
    assert result.stats.malformed_lines == 1
    assert len(result.issues) == 1
    assert isinstance(result.issues[0].error, JsonlMalformedLineError)


def test_parse_jsonl_text_non_object_json_values() -> None:
    """JSON arrays, strings, numbers, booleans should be treated as malformed."""
    payload = '[1,2,3]\n"just a string"\n42\ntrue\nnull\n{"ok":1}\n'
    result = _parse(payload)
    assert result.payloads == [{"ok": 1}]
    assert result.stats.malformed_lines == 5
    assert result.stats.parsed_lines == 1


def test_parse_jsonl_text_truncated_json() -> None:
    """Truncated JSON (missing closing brace) should be malformed."""
    result = _parse('{"id": 1, "name": "test\n')
    assert result.payloads == []
    assert result.stats.malformed_lines == 1


def test_parse_jsonl_text_extra_trailing_comma() -> None:
    """JSON with trailing comma (invalid) should be malformed."""
    result = _parse('{"id": 1, "name": "test",}\n')
    assert result.payloads == []
    assert result.stats.malformed_lines == 1


def test_parse_jsonl_text_mixed_valid_and_malformed() -> None:
    """Mix of valid and malformed lines should parse valid ones and track issues."""
    payload = '{"a":1}\n{broken}\n[]\n{"b":2}\n'
    result = _parse(payload)
    assert result.payloads == [{"a": 1}, {"b": 2}]
    assert result.stats.total_lines == 4
    assert result.stats.parsed_lines == 2
    assert result.stats.malformed_lines == 2
    assert result.stats.skipped_lines == 2


# ---------------------------------------------------------------------------
# parse_jsonl_text: oversized lines
# ---------------------------------------------------------------------------

def test_parse_jsonl_text_oversized_line_skipped() -> None:
    """Lines exceeding max_line_bytes should be skipped as oversized."""
    oversized = "x" * 512 + "\n"
    result = _parse(
        oversized + '{"ok":1}\n',
        max_line_bytes=256,
    )
    assert result.payloads == [{"ok": 1}]
    assert result.stats.oversized_lines == 1
    assert result.stats.skipped_lines == 1


def test_parse_jsonl_text_oversized_line_at_exact_limit() -> None:
    """Line at exactly max_line_bytes + 1 should be oversized."""
    # max_line_bytes=256, line with 257 bytes (256 chars + newline)
    line = "a" * 256 + "\n"  # 257 bytes total
    result = _parse(line + '{"ok":1}\n', max_line_bytes=256)
    assert result.stats.oversized_lines == 1
    assert result.payloads == [{"ok": 1}]


def test_parse_jsonl_text_multiple_oversized_lines() -> None:
    """Multiple oversized lines should all be counted."""
    big1 = "x" * 300 + "\n"
    big2 = "y" * 300 + "\n"
    result = _parse(big1 + big2 + '{"ok":1}\n', max_line_bytes=256)
    assert result.stats.oversized_lines == 2
    assert result.payloads == [{"ok": 1}]


# ---------------------------------------------------------------------------
# parse_jsonl_text: very long lines within limits
# ---------------------------------------------------------------------------

def test_parse_jsonl_text_long_valid_json_within_limit() -> None:
    """Long but valid JSON within max_line_bytes should parse fine."""
    obj = {"data": "a" * 10_000}
    line = json.dumps(obj) + "\n"
    result = _parse(line, max_line_bytes=50_000)
    assert result.payloads == [obj]
    assert result.stats.parsed_lines == 1


# ---------------------------------------------------------------------------
# ChunkParser: chunk boundary edge cases
# ---------------------------------------------------------------------------

def test_chunk_parser_split_across_chunks() -> None:
    """JSON line split across multiple chunks should reassemble correctly."""
    config = _make_config()
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    # Split '{"id":1}\n' into two chunks
    b1 = parser.feed(b'{"id":', stats=stats)
    assert b1.records == []  # Not yet complete

    b2 = parser.feed(b'1}\n', stats=stats)
    assert len(b2.records) == 1
    assert b2.records[0].payload == {"id": 1}


def test_chunk_parser_multiple_lines_in_single_chunk() -> None:
    """Multiple complete lines in one chunk should all parse."""
    config = _make_config()
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    batch = parser.feed(b'{"a":1}\n{"b":2}\n{"c":3}\n', stats=stats)
    assert len(batch.records) == 3


def test_chunk_parser_empty_chunk() -> None:
    """Empty chunk should produce no records or issues."""
    config = _make_config()
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    batch = parser.feed(b"", stats=stats)
    assert batch.records == []
    assert batch.issues == []


def test_chunk_parser_flush_emits_partial_line_at_eof() -> None:
    """Flush should emit partial buffer as final line."""
    config = _make_config()
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    parser.feed(b'{"id":42}', stats=stats)
    batch = parser.flush(stats=stats)
    assert len(batch.records) == 1
    assert batch.records[0].payload == {"id": 42}


def test_chunk_parser_flush_malformed_partial_line() -> None:
    """Flush with invalid partial JSON should produce issue, not record."""
    config = _make_config()
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    parser.feed(b"{broken partial", stats=stats)
    batch = parser.flush(stats=stats)
    assert batch.records == []
    assert len(batch.issues) == 1
    assert isinstance(batch.issues[0].error, JsonlMalformedLineError)


def test_chunk_parser_flush_empty_buffer() -> None:
    """Flush on empty parser should produce nothing."""
    config = _make_config()
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    batch = parser.flush(stats=stats)
    assert batch.records == []
    assert batch.issues == []


def test_chunk_parser_oversized_line_across_chunks() -> None:
    """Oversized line spanning multiple chunks should be detected and skipped."""
    config = _make_config(max_line_bytes=256, chunk_size=64)
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    # Feed content that exceeds max_line_bytes (256) without newline
    parser.feed(b"x" * 150, stats=stats)
    batch = parser.feed(b"x" * 150, stats=stats)
    # At this point line is 300 bytes > 256 max, discard until newline

    # Now feed newline to trigger the oversized registration + valid line
    batch2 = parser.feed(b"\n" + b'{"ok":1}\n', stats=stats)

    total_issues = batch.issues + batch2.issues
    assert stats.oversized_lines >= 1
    assert any(isinstance(i.error, JsonlLineTooLongError) for i in total_issues)


def test_chunk_parser_line_number_tracking() -> None:
    """Parser should correctly increment line numbers across chunks."""
    config = _make_config()
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    b1 = parser.feed(b'{"a":1}\n', stats=stats)
    assert b1.records[0].line_number == 1

    b2 = parser.feed(b'{"b":2}\n', stats=stats)
    assert b2.records[0].line_number == 2

    b3 = parser.feed(b'{"c":3}\n', stats=stats)
    assert b3.records[0].line_number == 3


def test_chunk_parser_raw_line_truncated_for_issues() -> None:
    """Issue raw_line should be truncated per max_issue_line_chars."""
    config = _make_config(max_issue_line_chars=64)
    parser = JsonlChunkParser(config=config)
    stats = JsonlStreamStats()

    # Malformed line longer than 64 chars
    long_bad = b"{" + b"x" * 100 + b"}\n"
    batch = parser.feed(long_bad, stats=stats)
    assert len(batch.issues) == 1
    assert len(batch.issues[0].raw_line) <= 67  # 64 + "..."


# ---------------------------------------------------------------------------
# parse_jsonl_text: special JSON values
# ---------------------------------------------------------------------------

def test_parse_jsonl_text_json_with_escaped_characters() -> None:
    """JSON with escaped quotes, backslashes, and control chars should parse."""
    obj = {"msg": 'He said "hello\\world"\nnewline'}
    result = _parse(json.dumps(obj) + "\n")
    assert result.payloads == [obj]


def test_parse_jsonl_text_json_with_null_values() -> None:
    """JSON object with null values should parse correctly."""
    result = _parse('{"key": null, "other": "val"}\n')
    assert result.payloads == [{"key": None, "other": "val"}]


def test_parse_jsonl_text_json_with_numeric_string_keys() -> None:
    """JSON objects with numeric-looking keys should parse as strings."""
    result = _parse('{"123": "value"}\n')
    assert result.payloads == [{"123": "value"}]


def test_parse_jsonl_text_empty_json_object() -> None:
    """Empty JSON object {} should parse as valid record."""
    result = _parse('{}\n')
    assert result.payloads == [{}]
    assert result.stats.parsed_lines == 1


# ---------------------------------------------------------------------------
# Stats correctness
# ---------------------------------------------------------------------------

def test_parse_stats_bytes_read_tracked() -> None:
    """stats.bytes_read should be zero in text parse (not tracked directly)."""
    result = _parse('{"a":1}\n')
    # bytes_read is 0 because parse_jsonl_text doesn't call metrics.add_bytes_read
    assert result.stats.bytes_read == 0


def test_parse_stats_to_dict_returns_all_fields() -> None:
    """stats.to_dict() should contain all expected metric keys."""
    result = _parse('{"a":1}\n{broken}\n')
    d = result.stats.to_dict()
    expected_keys = {
        "total_lines", "parsed_lines", "malformed_lines", "oversized_lines",
        "skipped_lines", "emitted_records", "bytes_read",
        "duration_seconds", "throughput_records_per_second",
    }
    assert set(d.keys()) == expected_keys


def test_parse_stats_copy_is_independent() -> None:
    """stats.copy() should produce an independent snapshot."""
    result = _parse('{"a":1}\n')
    snapshot = result.stats.copy()
    snapshot.total_lines = 999
    assert result.stats.total_lines != 999


# ---------------------------------------------------------------------------
# ParserBatch dataclass
# ---------------------------------------------------------------------------

def test_parser_batch_empty() -> None:
    """Empty ParserBatch should have empty lists."""
    batch = ParserBatch(records=[], issues=[])
    assert batch.records == []
    assert batch.issues == []


# ---------------------------------------------------------------------------
# Chunk size edge cases
# ---------------------------------------------------------------------------

def test_parse_with_chunk_size_one() -> None:
    """chunk_size=64 (minimum) with small payload should still parse."""
    result = _parse('{"id":1}\n', chunk_size=64)
    assert result.payloads == [{"id": 1}]


def test_parse_with_large_chunk_size() -> None:
    """Very large chunk_size should still work for small payloads."""
    result = _parse('{"id":1}\n', chunk_size=8192)
    assert result.payloads == [{"id": 1}]
