"""Edge-case focused tests for HtmlParser.parse_stream()."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from nocturna_engine.normalization.errors import ParseError

from tests.normalization.html.conftest import (
    html_table,
    make_parser,
    wrap_html,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _chunks_to_stream(chunks: list[bytes]) -> AsyncIterator[bytes]:
    """Convert a list of byte chunks to an async iterator."""
    for chunk in chunks:
        yield chunk


async def _empty_stream() -> AsyncIterator[bytes]:
    """Async iterator that yields nothing."""
    for _ in []:
        yield b""


# ---------------------------------------------------------------------------
# Basic streaming
# ---------------------------------------------------------------------------


class TestStreamBasic:
    """Multiple chunks accumulated and parsed correctly."""

    async def test_multiple_chunks_accumulated(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"], ["SQLi", "medium"]],
        )
        full = wrap_html(body).encode("utf-8")
        # Split into 3 chunks at arbitrary positions.
        mid1 = len(full) // 3
        mid2 = 2 * len(full) // 3
        chunks = [full[:mid1], full[mid1:mid2], full[mid2:]]
        result = await make_parser().parse_stream(_chunks_to_stream(chunks))
        assert len(result.findings) == 2

    async def test_chunks_byte_by_byte(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["Bug", "low"]],
        )
        full = wrap_html(body).encode("utf-8")
        chunks = [full[i : i + 1] for i in range(len(full))]
        result = await make_parser().parse_stream(_chunks_to_stream(chunks))
        assert len(result.findings) == 1

    async def test_two_chunks(self) -> None:
        body = html_table(
            ["Name", "Risk", "URL"],
            [["Alert", "High", "http://a"]],
        )
        full = wrap_html(body).encode("utf-8")
        mid = len(full) // 2
        chunks = [full[:mid], full[mid:]]
        result = await make_parser().parse_stream(_chunks_to_stream(chunks))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Single chunk
# ---------------------------------------------------------------------------


class TestStreamSingleChunk:
    """Single chunk works the same as parse()."""

    async def test_single_chunk(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"]],
        )
        full = wrap_html(body).encode("utf-8")
        result = await make_parser().parse_stream(_chunks_to_stream([full]))
        assert len(result.findings) == 1
        assert result.findings[0].title == "XSS"

    async def test_single_large_chunk(self) -> None:
        rows = [[f"Bug{i}", "medium"] for i in range(50)]
        body = html_table(["Vulnerability", "Severity"], rows)
        full = wrap_html(body).encode("utf-8")
        result = await make_parser().parse_stream(_chunks_to_stream([full]))
        assert len(result.findings) == 50


# ---------------------------------------------------------------------------
# Empty stream
# ---------------------------------------------------------------------------


class TestStreamEmpty:
    """Empty stream produces 0 findings."""

    async def test_empty_stream_no_findings(self) -> None:
        result = await make_parser().parse_stream(_empty_stream())
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0

    async def test_stream_with_empty_chunks(self) -> None:
        chunks = [b"", b"", b""]
        result = await make_parser().parse_stream(_chunks_to_stream(chunks))
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Size limit
# ---------------------------------------------------------------------------


class TestStreamSizeLimit:
    """Exceeding max_input_bytes raises ParseError."""

    async def test_exceeds_max_input_bytes(self) -> None:
        parser = make_parser(max_input_bytes=100)
        big_data = b"A" * 150
        with pytest.raises(ParseError):
            await parser.parse_stream(_chunks_to_stream([big_data]))

    async def test_cumulative_exceeds_max_input_bytes(self) -> None:
        parser = make_parser(max_input_bytes=100)
        chunks = [b"A" * 60, b"B" * 60]  # total = 120 > 100
        with pytest.raises(ParseError):
            await parser.parse_stream(_chunks_to_stream(chunks))

    async def test_exactly_at_limit_no_error(self) -> None:
        parser = make_parser(max_input_bytes=200)
        body = html_table(["Vulnerability", "Severity"], [["B", "low"]])
        full = wrap_html(body).encode("utf-8")
        # Ensure we stay within limit by padding or truncating
        if len(full) > 200:
            parser = make_parser(max_input_bytes=len(full))
        result = await parser.parse_stream(_chunks_to_stream([full]))
        assert isinstance(result.findings, list)

    async def test_parse_error_includes_parser_name(self) -> None:
        parser = make_parser(max_input_bytes=50)
        with pytest.raises(ParseError) as exc_info:
            await parser.parse_stream(_chunks_to_stream([b"X" * 100]))
        assert exc_info.value.source_parser == "html"


# ---------------------------------------------------------------------------
# Chunk boundaries
# ---------------------------------------------------------------------------


class TestStreamChunkBoundaries:
    """HTML tag split across chunk boundaries still parses correctly."""

    async def test_tag_split_across_chunks(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"]],
        )
        full = wrap_html(body).encode("utf-8")
        # Find a tag boundary and split there.
        split_at = full.index(b"<tr>") + 2  # split inside "<tr>"
        chunks = [full[:split_at], full[split_at:]]
        result = await make_parser().parse_stream(_chunks_to_stream(chunks))
        assert len(result.findings) >= 1

    async def test_split_in_cell_content(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["CrossSiteScripting", "high"]],
        )
        full = wrap_html(body).encode("utf-8")
        # Split inside cell text.
        idx = full.index(b"CrossSite") + 5
        chunks = [full[:idx], full[idx:]]
        result = await make_parser().parse_stream(_chunks_to_stream(chunks))
        assert len(result.findings) == 1
        assert result.findings[0].title == "CrossSiteScripting"

    async def test_split_between_tables(self) -> None:
        t1 = html_table(["Vulnerability", "Severity"], [["Bug1", "high"]])
        t2 = html_table(["Name", "Risk", "URL"], [["Bug2", "low", "http://a"]])
        full = wrap_html(t1 + t2).encode("utf-8")
        # Split between the two tables.
        split_at = full.index(t2.encode("utf-8")[:10])
        chunks = [full[:split_at], full[split_at:]]
        result = await make_parser().parse_stream(_chunks_to_stream(chunks))
        assert len(result.findings) == 2


# ---------------------------------------------------------------------------
# Stream equivalence
# ---------------------------------------------------------------------------


class TestStreamEquivalence:
    """parse_stream result must match parse result for same data."""

    async def test_equivalence_single_table(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity", "Target"],
            [["XSS", "high", "example.com"], ["SQLi", "critical", "db.local"]],
        )
        full_html = wrap_html(body)
        full_bytes = full_html.encode("utf-8")

        parser_batch = make_parser()
        parser_stream = make_parser()

        batch_result = await parser_batch.parse(full_html)
        stream_result = await parser_stream.parse_stream(_chunks_to_stream([full_bytes]))

        assert len(batch_result.findings) == len(stream_result.findings)
        for bf, sf in zip(batch_result.findings, stream_result.findings):
            assert bf.title == sf.title
            assert bf.severity == sf.severity
            assert bf.target == sf.target

    async def test_equivalence_multiple_tables(self) -> None:
        t1 = html_table(["Vulnerability", "Severity"], [["A", "high"]])
        t2 = html_table(["Name", "Risk", "URL"], [["B", "low", "http://x"]])
        full_html = wrap_html(t1 + t2)
        full_bytes = full_html.encode("utf-8")

        batch_result = await make_parser().parse(full_html)
        stream_result = await make_parser().parse_stream(
            _chunks_to_stream([full_bytes[:50], full_bytes[50:]])
        )

        assert len(batch_result.findings) == len(stream_result.findings)

    async def test_equivalence_empty(self) -> None:
        batch_result = await make_parser().parse("")
        stream_result = await make_parser().parse_stream(_empty_stream())
        assert len(batch_result.findings) == len(stream_result.findings) == 0

    async def test_equivalence_stats(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["X", "high"], ["", ""], ["Y", "low"]],
        )
        full_html = wrap_html(body)
        full_bytes = full_html.encode("utf-8")

        batch_result = await make_parser().parse(full_html)
        stream_result = await make_parser().parse_stream(_chunks_to_stream([full_bytes]))

        assert batch_result.stats.total_records_processed == stream_result.stats.total_records_processed
        assert batch_result.stats.findings_produced == stream_result.stats.findings_produced
        assert batch_result.stats.records_skipped == stream_result.stats.records_skipped
