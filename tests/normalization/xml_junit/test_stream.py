"""Tests for JunitXmlParser.parse_stream() — streaming mode.

Covers: basic streaming, chunked delivery, empty stream, malformed stream,
XXE protection, parity with batch parse.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from defusedxml import EntitiesForbidden

from nocturna_engine.normalization.parsers.xml_junit import JunitXmlParser

from tests.normalization.xml_junit.conftest import (
    junit_failure,
    make_parser,
    passed_testcase,
    junit_testcase,
    trivy_testcase,
    wrap_junit_single_suite,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _single_chunk_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _chunked_stream(data: bytes, chunk_size: int = 64) -> AsyncIterator[bytes]:
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


async def _empty_stream() -> AsyncIterator[bytes]:
    return
    yield  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Basic streaming
# ---------------------------------------------------------------------------


class TestStreamBasic:
    """Fundamental streaming scenarios."""

    async def test_single_chunk(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        ).encode("utf-8")
        result = await make_parser().parse_stream(_single_chunk_stream(xml))
        assert len(result.findings) == 1

    async def test_small_chunks(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln A", children_xml=junit_failure("a"))
            + junit_testcase(name="Vuln B", children_xml=junit_failure("b")),
        ).encode("utf-8")
        result = await make_parser().parse_stream(_chunked_stream(xml, chunk_size=32))
        assert len(result.findings) == 2

    async def test_very_small_chunks(self) -> None:
        """1-byte chunks stress test."""
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        ).encode("utf-8")
        result = await make_parser().parse_stream(_chunked_stream(xml, chunk_size=1))
        assert len(result.findings) == 1

    async def test_stream_with_mixed_pass_fail(self) -> None:
        cases = (
            junit_testcase(name="Fail One", children_xml=junit_failure("a"))
            + passed_testcase()
            + junit_testcase(name="Fail Two", children_xml=junit_failure("b"))
        )
        xml = wrap_junit_single_suite(cases).encode("utf-8")
        result = await make_parser().parse_stream(_single_chunk_stream(xml))
        assert len(result.findings) == 2
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# Empty / error streams
# ---------------------------------------------------------------------------


class TestStreamErrors:
    """Streaming error handling."""

    async def test_empty_stream(self) -> None:
        result = await make_parser().parse_stream(_empty_stream())
        assert len(result.findings) == 0

    async def test_malformed_xml_stream(self) -> None:
        result = await make_parser().parse_stream(
            _single_chunk_stream(b"<not valid xml<<<>>>"),
        )
        assert len(result.issues) >= 1
        assert result.stats.errors_encountered >= 1

    async def test_truncated_xml_stream(self) -> None:
        xml = b'<?xml version="1.0"?><testsuites><testsuite name="t"><testcase'
        result = await make_parser().parse_stream(_single_chunk_stream(xml))
        assert len(result.issues) >= 1


# ---------------------------------------------------------------------------
# XXE protection
# ---------------------------------------------------------------------------


class TestStreamXxeProtection:
    """Streaming blocks entity expansion attacks."""

    async def test_billion_laughs_blocked(self) -> None:
        payload = (
            b'<?xml version="1.0"?>'
            b"<!DOCTYPE z ["
            b'  <!ENTITY a "AAAAAAAAAA">'
            b'  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            b"]>"
            b"<testsuites><testsuite>"
            b'<testcase classname="c" name="n">'
            b"<failure>&c;</failure>"
            b"</testcase></testsuite></testsuites>"
        )
        with pytest.raises(EntitiesForbidden):
            await make_parser().parse_stream(_single_chunk_stream(payload))

    async def test_external_entity_blocked(self) -> None:
        payload = (
            b'<?xml version="1.0"?>'
            b"<!DOCTYPE z ["
            b'  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
            b"]>"
            b"<testsuites><testsuite>"
            b'<testcase classname="c" name="n">'
            b"<failure>&xxe;</failure>"
            b"</testcase></testsuite></testsuites>"
        )
        with pytest.raises(EntitiesForbidden):
            await make_parser().parse_stream(_single_chunk_stream(payload))


# ---------------------------------------------------------------------------
# Parity with batch parse
# ---------------------------------------------------------------------------


class TestStreamBatchParity:
    """Stream and batch produce identical results."""

    async def test_findings_match(self) -> None:
        xml_str = wrap_junit_single_suite(
            trivy_testcase("CVE-2024-0001", "openssl", "CRITICAL")
            + passed_testcase()
            + trivy_testcase("CVE-2024-0002", "libcurl", "HIGH"),
        )
        xml_bytes = xml_str.encode("utf-8")

        parser = make_parser(tool_name="trivy")
        batch_result = await parser.parse(xml_str)
        stream_result = await parser.parse_stream(_single_chunk_stream(xml_bytes))

        assert len(batch_result.findings) == len(stream_result.findings)
        assert batch_result.stats.total_records_processed == stream_result.stats.total_records_processed
        assert batch_result.stats.findings_produced == stream_result.stats.findings_produced
        assert batch_result.stats.records_skipped == stream_result.stats.records_skipped

    async def test_titles_match(self) -> None:
        xml_str = wrap_junit_single_suite(
            junit_testcase(name="Vuln A", children_xml=junit_failure("a"))
            + junit_testcase(name="Vuln B", children_xml=junit_failure("b")),
        )
        xml_bytes = xml_str.encode("utf-8")

        parser = make_parser()
        batch_result = await parser.parse(xml_str)
        stream_result = await parser.parse_stream(_single_chunk_stream(xml_bytes))

        batch_titles = {f.title for f in batch_result.findings}
        stream_titles = {f.title for f in stream_result.findings}
        assert batch_titles == stream_titles
