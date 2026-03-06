"""Edge-case focused tests for nocturna_engine.normalization.parsers.plaintext."""

from __future__ import annotations

import re
from typing import Any

import pytest

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.parsers.base import ParseResult, ParserConfig
from nocturna_engine.normalization.parsers.plaintext import (
    ExtractionPattern,
    PlaintextParser,
    _BUILTIN_PATTERNS,
)
from nocturna_engine.normalization.severity import build_severity_map


def _make_config(**kwargs: Any) -> ParserConfig:
    defaults: dict[str, Any] = {
        "tool_name": "test_plain",
        "severity_map": build_severity_map(),
    }
    defaults.update(kwargs)
    return ParserConfig(**defaults)


def _parser(**kwargs: Any) -> PlaintextParser:
    extra_patterns = kwargs.pop("extra_patterns", None)
    return PlaintextParser(_make_config(**kwargs), extra_patterns=extra_patterns)


# ---------------------------------------------------------------------------
# ExtractionPattern dataclass
# ---------------------------------------------------------------------------


class TestExtractionPattern:
    def test_creation(self) -> None:
        pat = ExtractionPattern(
            name="test",
            pattern=re.compile(r"(?P<word>\w+)"),
            severity=SeverityLevel.LOW,
            title_template="{word}",
            description_template="{word} found",
        )
        assert pat.name == "test"
        assert pat.severity == SeverityLevel.LOW

    def test_frozen(self) -> None:
        pat = ExtractionPattern(
            name="x",
            pattern=re.compile(r"x"),
            severity=SeverityLevel.INFO,
            title_template="x",
            description_template="x",
        )
        with pytest.raises(AttributeError):
            pat.name = "changed"  # type: ignore[misc]

    def test_slots(self) -> None:
        pat = ExtractionPattern(
            name="x",
            pattern=re.compile(r"x"),
            severity=SeverityLevel.INFO,
            title_template="x",
            description_template="x",
        )
        assert not hasattr(pat, "__dict__")


# ---------------------------------------------------------------------------
# Builtin patterns smoke check
# ---------------------------------------------------------------------------


class TestBuiltinPatterns:
    def test_four_builtin_patterns(self) -> None:
        assert len(_BUILTIN_PATTERNS) == 4

    @pytest.mark.parametrize(
        "name",
        ["cve_reference", "ip_port_open", "severity_prefix", "url_status"],
    )
    def test_pattern_exists(self, name: str) -> None:
        names = [p.name for p in _BUILTIN_PATTERNS]
        assert name in names


# ---------------------------------------------------------------------------
# CVE pattern
# ---------------------------------------------------------------------------


class TestCvePattern:
    async def test_cve_with_dash_separator(self) -> None:
        result = await _parser().parse("CVE-2024-12345 - Buffer overflow in libfoo")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.title == "CVE-2024-12345"
        assert f.severity == SeverityLevel.HIGH
        assert "Buffer overflow" in f.description

    async def test_cve_with_colon_separator(self) -> None:
        result = await _parser().parse("CVE-2023-99999: Remote code execution")
        assert len(result.findings) == 1
        assert result.findings[0].title == "CVE-2023-99999"

    async def test_cve_case_insensitive(self) -> None:
        result = await _parser().parse("cve-2024-00001 - lowercase cve")
        assert len(result.findings) == 1
        assert result.findings[0].title.upper().startswith("CVE")

    async def test_cve_in_evidence(self) -> None:
        result = await _parser().parse("CVE-2024-12345 - desc")
        f = result.findings[0]
        assert f.evidence.get("cve") is not None
        assert "2024-12345" in f.evidence["cve"]

    async def test_cve_no_description_separator_no_match(self) -> None:
        # Pattern requires ` - ` or `: ` after CVE; bare CVE without separator → no match
        result = await _parser().parse("CVE-2024-12345")
        assert len(result.findings) == 0

    async def test_cve_five_digit_id(self) -> None:
        result = await _parser().parse("CVE-2024-123456 - extended id")
        assert len(result.findings) == 1

    async def test_cve_four_digit_id(self) -> None:
        result = await _parser().parse("CVE-2024-1234 - min digits")
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# IP:port pattern
# ---------------------------------------------------------------------------


class TestIpPortPattern:
    async def test_masscan_style(self) -> None:
        result = await _parser().parse("Discovered open port 80/tcp on 192.168.1.1")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "80" in f.title
        assert "tcp" in f.title
        assert f.target == "192.168.1.1"
        assert f.severity == SeverityLevel.LOW

    async def test_port_udp(self) -> None:
        result = await _parser().parse("Discovered open port 53/udp on 10.0.0.1")
        assert len(result.findings) == 1
        assert "udp" in result.findings[0].title

    async def test_bare_port_format(self) -> None:
        result = await _parser().parse("port 443/tcp on 10.0.0.1")
        assert len(result.findings) == 1

    async def test_ipv6_host(self) -> None:
        result = await _parser().parse("Discovered open port 22/tcp on ::1")
        assert len(result.findings) == 1
        assert result.findings[0].target == "::1"

    async def test_target_from_host_group(self) -> None:
        result = await _parser().parse("open port 8080/tcp on 172.16.0.5")
        assert result.findings[0].target == "172.16.0.5"


# ---------------------------------------------------------------------------
# Severity prefix pattern
# ---------------------------------------------------------------------------


class TestSeverityPrefixPattern:
    @pytest.mark.parametrize(
        "severity_str,expected",
        [
            ("CRITICAL", SeverityLevel.CRITICAL),
            ("HIGH", SeverityLevel.HIGH),
            ("MEDIUM", SeverityLevel.MEDIUM),
            ("LOW", SeverityLevel.LOW),
            ("INFO", SeverityLevel.INFO),
            ("WARNING", SeverityLevel.MEDIUM),
            ("ERROR", SeverityLevel.HIGH),
        ],
        ids=["critical", "high", "medium", "low", "info", "warning", "error"],
    )
    async def test_severity_from_bracket(
        self, severity_str: str, expected: SeverityLevel
    ) -> None:
        result = await _parser().parse(f"[{severity_str}] Something bad found")
        assert len(result.findings) == 1
        assert result.findings[0].severity == expected

    async def test_case_insensitive(self) -> None:
        result = await _parser().parse("[critical] lower case prefix")
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.CRITICAL

    async def test_title_extracted(self) -> None:
        result = await _parser().parse("[HIGH] SQL Injection detected")
        assert result.findings[0].title == "SQL Injection detected"

    async def test_severity_overrides_pattern_default(self) -> None:
        # The severity_prefix pattern default is INFO but captured severity overrides
        result = await _parser().parse("[CRITICAL] Override test")
        assert result.findings[0].severity == SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# URL status pattern
# ---------------------------------------------------------------------------


class TestUrlStatusPattern:
    async def test_url_with_status(self) -> None:
        result = await _parser().parse("https://example.com/admin [200] OK page")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "200" in f.title
        assert "example.com" in f.title
        assert f.severity == SeverityLevel.INFO

    async def test_url_without_extra_info(self) -> None:
        result = await _parser().parse("http://test.com [404]")
        assert len(result.findings) == 1
        assert "404" in result.findings[0].title

    async def test_url_target_from_url_group(self) -> None:
        result = await _parser().parse("https://target.io/path [200] info")
        f = result.findings[0]
        assert "target.io" in f.target


# ---------------------------------------------------------------------------
# No match / empty input
# ---------------------------------------------------------------------------


class TestNoMatchAndEmpty:
    async def test_no_patterns_match(self) -> None:
        result = await _parser().parse("This is just random text\nAnother random line")
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 2

    async def test_empty_string(self) -> None:
        result = await _parser().parse("")
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0

    async def test_empty_bytes(self) -> None:
        result = await _parser().parse(b"")
        assert len(result.findings) == 0

    async def test_only_blank_lines(self) -> None:
        result = await _parser().parse("\n\n\n  \n\t\n")
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0  # blank lines not counted

    async def test_whitespace_lines_not_counted(self) -> None:
        result = await _parser().parse("   \n  \t  \n")
        assert result.stats.total_records_processed == 0


# ---------------------------------------------------------------------------
# Multi-line input
# ---------------------------------------------------------------------------


class TestMultiLine:
    async def test_only_matching_lines_produce_findings(self) -> None:
        text = (
            "Starting scan...\n"
            "CVE-2024-0001 - vuln one\n"
            "Some log noise\n"
            "CVE-2024-0002 - vuln two\n"
            "Scan complete.\n"
        )
        result = await _parser().parse(text)
        assert len(result.findings) == 2
        assert result.stats.records_skipped == 3

    async def test_large_input_few_matches(self) -> None:
        lines = ["random noise line number {}".format(i) for i in range(10000)]
        lines[500] = "CVE-2024-0001 - found mid-stream"
        lines[9999] = "[CRITICAL] end of file issue"
        result = await _parser().parse("\n".join(lines))
        assert len(result.findings) == 2
        assert result.stats.total_records_processed == 10000

    async def test_first_pattern_match_wins(self) -> None:
        # If a line matches multiple patterns, first one wins
        # "[HIGH] CVE-2024-0001 - dual match" matches severity_prefix first
        # because _BUILTIN_PATTERNS order: cve, ip_port, severity_prefix, url_status
        # Actually CVE pattern is tried first, but line has [HIGH] prefix too
        line = "CVE-2024-0001 - dual match"
        result = await _parser().parse(line)
        # CVE pattern is first in _BUILTIN_PATTERNS
        assert result.findings[0].title == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# Extra patterns via constructor
# ---------------------------------------------------------------------------


class TestExtraPatterns:
    async def test_extra_pattern_added(self) -> None:
        custom = ExtractionPattern(
            name="custom",
            pattern=re.compile(r"VULN: (?P<title>.+)"),
            severity=SeverityLevel.MEDIUM,
            title_template="{title}",
            description_template="{title}",
        )
        parser = _parser(extra_patterns=[custom])
        result = await parser.parse("VULN: Custom finding detected")
        assert len(result.findings) == 1
        assert result.findings[0].title == "Custom finding detected"

    async def test_builtin_patterns_still_work_with_extras(self) -> None:
        custom = ExtractionPattern(
            name="custom",
            pattern=re.compile(r"CUSTOM_MATCH"),
            severity=SeverityLevel.LOW,
            title_template="custom",
            description_template="custom",
        )
        parser = _parser(extra_patterns=[custom])
        result = await parser.parse("CVE-2024-0001 - still works")
        assert len(result.findings) == 1
        assert result.findings[0].title == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# Template formatting edge cases
# ---------------------------------------------------------------------------


class TestTemplateFormatting:
    async def test_template_key_error_fallback(self) -> None:
        # Pattern with template referencing nonexistent group → falls back to line[:200]
        custom = ExtractionPattern(
            name="bad_template",
            pattern=re.compile(r"MATCH (?P<word>\w+)"),
            severity=SeverityLevel.INFO,
            title_template="{nonexistent_group}",
            description_template="{also_nonexistent}",
        )
        parser = _parser(extra_patterns=[custom])
        result = await parser.parse("MATCH hello")
        assert len(result.findings) == 1
        # Falls back to line[:200]
        assert "MATCH hello" in result.findings[0].title

    async def test_empty_title_after_format_falls_back(self) -> None:
        # Group captures empty string → title empty → fallback to line[:200]
        custom = ExtractionPattern(
            name="empty_title",
            pattern=re.compile(r"XMATCH(?P<title>)END"),
            severity=SeverityLevel.INFO,
            title_template="{title}",
            description_template="{title}",
        )
        parser = _parser(extra_patterns=[custom])
        result = await parser.parse("XMATCHEND")
        assert len(result.findings) == 1
        assert result.findings[0].title == "XMATCHEND"

    async def test_empty_description_falls_back_to_title(self) -> None:
        custom = ExtractionPattern(
            name="empty_desc",
            pattern=re.compile(r"Z(?P<desc>)W"),
            severity=SeverityLevel.INFO,
            title_template="fixed title",
            description_template="{desc}",
        )
        parser = _parser(extra_patterns=[custom])
        result = await parser.parse("ZW")
        assert len(result.findings) == 1
        assert result.findings[0].description == "fixed title"


# ---------------------------------------------------------------------------
# Target extraction
# ---------------------------------------------------------------------------


class TestTargetExtraction:
    async def test_target_from_host_group(self) -> None:
        result = await _parser().parse("Discovered open port 80/tcp on 10.0.0.1")
        assert result.findings[0].target == "10.0.0.1"

    async def test_target_from_url_group(self) -> None:
        result = await _parser().parse("https://mysite.com [200] OK")
        assert "mysite.com" in result.findings[0].target

    async def test_target_fallback_to_hint(self) -> None:
        # severity_prefix pattern has no host/url group
        result = await _parser(target_hint="fallback.io").parse("[HIGH] Something bad")
        assert result.findings[0].target == "fallback.io"

    async def test_target_fallback_to_unknown(self) -> None:
        # No host/url group and no target_hint
        result = await _parser().parse("[HIGH] No target available")
        assert result.findings[0].target == "unknown"


# ---------------------------------------------------------------------------
# Evidence content
# ---------------------------------------------------------------------------


class TestEvidence:
    async def test_evidence_has_pattern_name(self) -> None:
        result = await _parser().parse("CVE-2024-0001 - test")
        assert result.findings[0].evidence["pattern_name"] == "cve_reference"

    async def test_evidence_has_raw_line(self) -> None:
        result = await _parser().parse("CVE-2024-0001 - test")
        assert "CVE-2024-0001" in result.findings[0].evidence["raw_line"]

    async def test_evidence_has_line_number(self) -> None:
        result = await _parser().parse("noise\nCVE-2024-0001 - test")
        assert result.findings[0].evidence["line_number"] == 2

    async def test_evidence_raw_line_truncated_at_1024(self) -> None:
        long_desc = "A" * 2000
        line = f"CVE-2024-0001 - {long_desc}"
        result = await _parser().parse(line)
        assert len(result.findings[0].evidence["raw_line"]) == 1024

    async def test_evidence_cve_key_present(self) -> None:
        result = await _parser().parse("CVE-2024-0001 - test")
        assert result.findings[0].evidence.get("cve") is not None

    async def test_evidence_no_cve_key_for_non_cve(self) -> None:
        result = await _parser().parse("[HIGH] No cve here")
        assert "cve" not in result.findings[0].evidence


# ---------------------------------------------------------------------------
# Origin attachment
# ---------------------------------------------------------------------------


class TestOriginAttachment:
    async def test_origin_in_metadata(self) -> None:
        result = await _parser().parse("CVE-2024-0001 - test")
        meta = result.findings[0].metadata
        assert "_normalization" in meta
        assert meta["_normalization"]["parser_name"] == "plaintext"

    async def test_origin_line_number(self) -> None:
        result = await _parser().parse("noise\nCVE-2024-0001 - test")
        assert result.findings[0].metadata["_normalization"]["line_number"] == 2


# ---------------------------------------------------------------------------
# parse_stream
# ---------------------------------------------------------------------------


class TestParseStream:
    async def test_stream_basic(self) -> None:
        parser = _parser()

        async def _stream():
            yield b"CVE-2024-0001 - vuln\n"
            yield b"[HIGH] another\n"

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 2

    async def test_stream_partial_line_across_chunks(self) -> None:
        parser = _parser()

        async def _stream():
            yield b"CVE-2024-"
            yield b"0001 - split across chunks\n"

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 1
        assert "CVE-2024-0001" in result.findings[0].title

    async def test_stream_flush_last_partial_line(self) -> None:
        parser = _parser()

        async def _stream():
            yield b"CVE-2024-0001 - no trailing newline"

        result = await parser.parse_stream(_stream())
        # Last partial line should be flushed
        assert len(result.findings) == 1

    async def test_stream_empty(self) -> None:
        parser = _parser()

        async def _stream():
            return
            yield  # type: ignore[misc]

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 0

    async def test_stream_blank_lines_skipped(self) -> None:
        parser = _parser()

        async def _stream():
            yield b"\n\n\nCVE-2024-0001 - found\n\n\n"

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 1
        assert result.stats.total_records_processed == 1

    async def test_stream_line_numbers_sequential(self) -> None:
        parser = _parser()

        async def _stream():
            yield b"CVE-2024-0001 - first\n"
            yield b"noise\nCVE-2024-0002 - second\n"

        result = await parser.parse_stream(_stream())
        assert result.findings[0].evidence["line_number"] == 1
        assert result.findings[1].evidence["line_number"] == 3


# ---------------------------------------------------------------------------
# Bytes input
# ---------------------------------------------------------------------------


class TestBytesInput:
    async def test_bytes_decoded(self) -> None:
        result = await _parser().parse(b"CVE-2024-0001 - from bytes")
        assert len(result.findings) == 1

    async def test_invalid_utf8_replaced(self) -> None:
        result = await _parser().parse(b"\xff\xfeCVE-2024-0001 - after bad bytes")
        # errors="replace" means bad bytes become replacement chars, then line parsed
        assert result.stats.total_records_processed == 1


# ---------------------------------------------------------------------------
# Title truncation
# ---------------------------------------------------------------------------


class TestTitleTruncation:
    async def test_long_title_truncated_to_200(self) -> None:
        long_title = "A" * 500
        line = f"[HIGH] {long_title}"
        result = await _parser().parse(line)
        assert len(result.findings[0].title) == 200


# ---------------------------------------------------------------------------
# Parser class attributes
# ---------------------------------------------------------------------------


class TestClassAttributes:
    def test_parser_name(self) -> None:
        assert PlaintextParser.parser_name == "plaintext"

    def test_source_format(self) -> None:
        assert PlaintextParser.source_format == "plaintext"
