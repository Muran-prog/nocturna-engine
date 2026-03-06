"""Edge-case focused tests for nocturna_engine.normalization.parsers.csv_generic."""

from __future__ import annotations

from typing import Any

import pytest

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.parsers.base import ParseResult, ParserConfig
from nocturna_engine.normalization.parsers.csv_generic import (
    GenericCsvParser,
    _COLUMN_ALIASES,
    _find_column,
)
from nocturna_engine.normalization.severity import build_severity_map


def _make_config(**kwargs: Any) -> ParserConfig:
    defaults: dict[str, Any] = {
        "tool_name": "test_csv",
        "severity_map": build_severity_map(),
    }
    defaults.update(kwargs)
    return ParserConfig(**defaults)


def _parser(**kwargs: Any) -> GenericCsvParser:
    return GenericCsvParser(_make_config(**kwargs))


# ---------------------------------------------------------------------------
# _find_column helper
# ---------------------------------------------------------------------------


class TestFindColumn:
    """Edge cases for column alias matching."""

    def test_exact_match(self) -> None:
        assert _find_column(["title", "severity"], ["title"]) == 0

    def test_partial_match(self) -> None:
        # "vulnerability_name" contains "vulnerability" alias for title
        assert _find_column(["vulnerability_name"], ["vulnerability"]) == 0

    def test_no_match(self) -> None:
        assert _find_column(["foo", "bar"], ["title", "name"]) is None

    def test_case_insensitive_headers(self) -> None:
        # headers are already lowercased by the parser
        assert _find_column(["title"], ["title"]) == 0

    def test_first_alias_wins(self) -> None:
        headers = ["name", "title"]
        # "title" alias appears before "name" in the alias list for "title"
        assert _find_column(headers, ["title", "name"]) == 1

    def test_empty_headers(self) -> None:
        assert _find_column([], ["title"]) is None

    def test_empty_aliases(self) -> None:
        assert _find_column(["title"], []) is None

    @pytest.mark.parametrize(
        "alias,headers,expected",
        [
            ("vulnerability", ["vulnerability"], 0),
            ("finding", ["my_finding_col"], 0),
            ("rule", ["rule"], 0),
            ("check", ["security_check"], 0),
            ("issue", ["issue"], 0),
        ],
        ids=["exact-vuln", "partial-finding", "exact-rule", "partial-check", "exact-issue"],
    )
    def test_title_aliases(self, alias: str, headers: list[str], expected: int) -> None:
        assert _find_column(headers, [alias]) == expected

    @pytest.mark.parametrize(
        "alias",
        ["risk", "priority", "level", "rating", "impact"],
    )
    def test_severity_aliases(self, alias: str) -> None:
        assert _find_column([alias], [alias]) == 0


# ---------------------------------------------------------------------------
# Header detection and column mapping
# ---------------------------------------------------------------------------


class TestHeaderDetection:
    """Standard and unusual headers."""

    async def test_standard_headers(self) -> None:
        csv = "title,severity,target,description\nXSS,high,example.com,Cross-site scripting"
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        assert result.findings[0].title == "XSS"
        assert result.findings[0].severity == SeverityLevel.HIGH

    async def test_alias_headers_vulnerability_risk(self) -> None:
        csv = "vulnerability,risk,host\nSQLi,critical,db.local"
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        assert result.findings[0].title == "SQLi"
        assert result.findings[0].severity == SeverityLevel.CRITICAL
        assert result.findings[0].target == "db.local"

    async def test_missing_title_column_all_skipped(self) -> None:
        csv = "severity,target\nhigh,example.com\nmedium,other.com"
        result = await _parser().parse(csv)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 2

    async def test_extra_columns_no_error(self) -> None:
        csv = "title,severity,extra1,extra2\nBug,low,foo,bar"
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        assert len(result.issues) == 0


# ---------------------------------------------------------------------------
# Delimiter detection
# ---------------------------------------------------------------------------


class TestDelimiterDetection:
    """Comma vs. tab detection edge cases."""

    async def test_tab_delimiter(self) -> None:
        tsv = "title\tseverity\ttarget\nXSS\thigh\texample.com"
        result = await _parser().parse(tsv)
        assert len(result.findings) == 1
        assert result.findings[0].title == "XSS"

    async def test_comma_wins_when_equal(self) -> None:
        # If comma and tab count are equal, comma wins (count equal → not >)
        mixed = "title,severity\ttarget\nXSS,high\texample.com"
        p = _parser()
        delimiter = p._detect_delimiter(mixed)
        assert delimiter == ","

    async def test_tabs_dominate(self) -> None:
        # More tabs → tab wins
        tsv_heavy = "title\tseverity\ttarget\tdescription"
        p = _parser()
        assert p._detect_delimiter(tsv_heavy) == "\t"


# ---------------------------------------------------------------------------
# Empty and minimal CSV
# ---------------------------------------------------------------------------


class TestEmptyAndMinimal:
    """Edge cases for empty/minimal CSV data."""

    async def test_empty_string(self) -> None:
        result = await _parser().parse("")
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0

    async def test_empty_bytes(self) -> None:
        result = await _parser().parse(b"")
        assert len(result.findings) == 0

    async def test_header_only_no_data(self) -> None:
        csv = "title,severity,target"
        result = await _parser().parse(csv)
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0

    async def test_single_newline(self) -> None:
        result = await _parser().parse("\n")
        assert len(result.findings) == 0

    async def test_only_empty_rows(self) -> None:
        csv = "title,severity\n,,\n,,\n"
        result = await _parser().parse(csv)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 2


# ---------------------------------------------------------------------------
# Quoted fields with special characters
# ---------------------------------------------------------------------------


class TestQuotedFields:
    """CSV quoting edge cases."""

    async def test_commas_inside_quotes(self) -> None:
        csv = 'title,severity,target\n"title,with,commas",high,example.com'
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        assert result.findings[0].title == "title,with,commas"

    async def test_newlines_inside_quotes(self) -> None:
        csv = 'title,severity,target\n"title with\nnewline",high,example.com'
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        assert "newline" in result.findings[0].title

    async def test_double_quotes_inside_quotes(self) -> None:
        csv = 'title,severity,target\n"has ""double"" quotes",low,x.com'
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        assert 'has "double" quotes' == result.findings[0].title


# ---------------------------------------------------------------------------
# Row edge cases
# ---------------------------------------------------------------------------


class TestRowEdgeCases:
    """Row-level boundary conditions."""

    async def test_empty_row_skipped(self) -> None:
        csv = "title,severity\nXSS,high\n,,\nSQLi,medium"
        result = await _parser().parse(csv)
        assert len(result.findings) == 2
        assert result.stats.records_skipped == 1

    async def test_row_more_cells_than_headers(self) -> None:
        csv = "title,severity\nXSS,high,extra_cell1,extra_cell2"
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        assert result.findings[0].title == "XSS"

    async def test_row_fewer_cells_than_headers(self) -> None:
        csv = "title,severity,target,description\nXSS"
        result = await _parser().parse(csv)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.title == "XSS"
        # severity defaults to "info" when _get_cell returns ""
        assert f.severity == SeverityLevel.INFO
        # target falls back to target_hint or "unknown"
        assert f.target == "unknown"

    async def test_row_fewer_cells_with_target_hint(self) -> None:
        csv = "title,severity\nXSS"
        result = await _parser(target_hint="fallback.com").parse(csv)
        assert result.findings[0].target == "fallback.com"

    async def test_whitespace_only_cells(self) -> None:
        csv = "title,severity\n   ,   "
        result = await _parser().parse(csv)
        # All whitespace row → still processed but empty title → skipped
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# CVSS column edge cases
# ---------------------------------------------------------------------------


class TestCvssColumn:
    """CVSS score parsing boundary conditions."""

    @pytest.mark.parametrize(
        "cvss_val,expected",
        [
            ("7.5", 7.5),
            ("0.0", 0.0),
            ("10.0", 10.0),
            ("0.1", 0.1),
        ],
        ids=["mid", "zero", "max", "minimal"],
    )
    async def test_valid_cvss(self, cvss_val: str, expected: float) -> None:
        csv = f"title,cvss\nBug,{cvss_val}"
        result = await _parser().parse(csv)
        assert result.findings[0].cvss == expected

    @pytest.mark.parametrize(
        "cvss_val",
        ["-0.1", "10.1", "100", "-5"],
        ids=["below-zero", "above-ten", "way-high", "negative"],
    )
    async def test_out_of_range_cvss_ignored(self, cvss_val: str) -> None:
        csv = f"title,cvss\nBug,{cvss_val}"
        result = await _parser().parse(csv)
        assert result.findings[0].cvss is None

    @pytest.mark.parametrize(
        "cvss_val",
        ["abc", "N/A", "", "high", "  "],
        ids=["text", "na", "empty", "severity-word", "whitespace"],
    )
    async def test_non_numeric_cvss_ignored(self, cvss_val: str) -> None:
        csv = f"title,cvss\nBug,{cvss_val}"
        result = await _parser().parse(csv)
        assert result.findings[0].cvss is None


# ---------------------------------------------------------------------------
# CWE column
# ---------------------------------------------------------------------------


class TestCweColumn:
    async def test_cwe_mapped(self) -> None:
        csv = "title,cwe\nXSS,CWE-79"
        result = await _parser().parse(csv)
        assert result.findings[0].cwe == "CWE-79"

    async def test_cwe_missing(self) -> None:
        csv = "title\nXSS"
        result = await _parser().parse(csv)
        assert result.findings[0].cwe is None

    async def test_cwe_empty_cell(self) -> None:
        csv = "title,cwe\nXSS,"
        result = await _parser().parse(csv)
        assert result.findings[0].cwe is None

    async def test_cwe_id_alias(self) -> None:
        csv = "title,cwe_id\nXSS,CWE-79"
        result = await _parser().parse(csv)
        assert result.findings[0].cwe == "CWE-79"


# ---------------------------------------------------------------------------
# Tool column override
# ---------------------------------------------------------------------------


class TestToolColumn:
    async def test_tool_from_csv_column(self) -> None:
        csv = "title,tool\nBug,nikto"
        result = await _parser().parse(csv)
        assert result.findings[0].tool == "nikto"

    async def test_tool_fallback_to_config(self) -> None:
        csv = "title\nBug"
        result = await _parser().parse(csv)
        assert result.findings[0].tool == "test_csv"

    async def test_tool_empty_cell_fallback(self) -> None:
        csv = "title,tool\nBug,"
        result = await _parser().parse(csv)
        assert result.findings[0].tool == "test_csv"


# ---------------------------------------------------------------------------
# Title truncation
# ---------------------------------------------------------------------------


class TestTitleTruncation:
    async def test_very_long_title_truncated(self) -> None:
        long_title = "A" * 300
        csv = f"title\n{long_title}"
        result = await _parser().parse(csv)
        assert len(result.findings[0].title) == 200

    async def test_exactly_200_not_truncated(self) -> None:
        title = "A" * 200
        csv = f"title\n{title}"
        result = await _parser().parse(csv)
        assert result.findings[0].title == title


# ---------------------------------------------------------------------------
# Severity mapping integration
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", SeverityLevel.CRITICAL),
            ("CRITICAL", SeverityLevel.CRITICAL),
            ("high", SeverityLevel.HIGH),
            ("HIGH", SeverityLevel.HIGH),
            ("medium", SeverityLevel.MEDIUM),
            ("low", SeverityLevel.LOW),
            ("info", SeverityLevel.INFO),
            ("informational", SeverityLevel.INFO),
            ("warning", SeverityLevel.MEDIUM),
            ("unknown_garbage", SeverityLevel.INFO),
        ],
        ids=[
            "critical", "CRITICAL", "high", "HIGH",
            "medium", "low", "info", "informational",
            "warning", "unmapped-falls-to-info",
        ],
    )
    async def test_severity_resolution(self, raw: str, expected: SeverityLevel) -> None:
        csv = f"title,severity\nBug,{raw}"
        result = await _parser().parse(csv)
        assert result.findings[0].severity == expected

    async def test_missing_severity_defaults_info(self) -> None:
        csv = "title\nBug"
        result = await _parser().parse(csv)
        assert result.findings[0].severity == SeverityLevel.INFO


# ---------------------------------------------------------------------------
# Description fallback
# ---------------------------------------------------------------------------


class TestDescriptionFallback:
    async def test_description_from_column(self) -> None:
        csv = "title,description\nBug,Detailed description"
        result = await _parser().parse(csv)
        assert result.findings[0].description == "Detailed description"

    async def test_description_falls_back_to_title(self) -> None:
        csv = "title\nMy Bug Title"
        result = await _parser().parse(csv)
        assert result.findings[0].description == "My Bug Title"


# ---------------------------------------------------------------------------
# Evidence and origin
# ---------------------------------------------------------------------------


class TestEvidenceAndOrigin:
    async def test_evidence_has_csv_row(self) -> None:
        csv = "title\nBug"
        result = await _parser().parse(csv)
        assert result.findings[0].evidence["csv_row"] == 2

    async def test_origin_attached(self) -> None:
        csv = "title\nBug"
        result = await _parser().parse(csv)
        meta = result.findings[0].metadata
        assert "_normalization" in meta
        assert meta["_normalization"]["parser_name"] == "csv_generic"
        assert meta["_normalization"]["tool_name"] == "test_csv"

    async def test_origin_line_number(self) -> None:
        csv = "title\nFirst\nSecond"
        result = await _parser().parse(csv)
        meta0 = result.findings[0].metadata["_normalization"]
        meta1 = result.findings[1].metadata["_normalization"]
        assert meta0["line_number"] == 2
        assert meta1["line_number"] == 3


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------


class TestStatsTracking:
    async def test_stats_all_parsed(self) -> None:
        csv = "title\nAlpha\nBravo\nCharlie"
        result = await _parser().parse(csv)
        assert result.stats.total_records_processed == 3
        assert result.stats.findings_produced == 3

    async def test_stats_mixed(self) -> None:
        csv = "title\nValid Row\n,,\n"
        result = await _parser().parse(csv)
        assert result.stats.findings_produced == 1
        assert result.stats.records_skipped >= 1


# ---------------------------------------------------------------------------
# parse_stream
# ---------------------------------------------------------------------------


class TestParseStream:
    async def test_parse_stream_accumulates(self) -> None:
        parser = _parser()
        chunks = [b"title,severity\n", b"XSS,high\n", b"SQLi,medium"]

        async def _stream():
            for c in chunks:
                yield c

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 2

    async def test_parse_stream_empty(self) -> None:
        parser = _parser()

        async def _stream():
            return
            yield  # type: ignore[misc]  # make it an async gen

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 0

    async def test_parse_stream_single_chunk(self) -> None:
        parser = _parser()
        data = b"title\nBug"

        async def _stream():
            yield data

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Bytes input
# ---------------------------------------------------------------------------


class TestBytesInput:
    async def test_bytes_decoded(self) -> None:
        csv = b"title,severity\nXSS,high"
        result = await _parser().parse(csv)
        assert len(result.findings) == 1

    async def test_utf8_with_bom(self) -> None:
        csv = b"\xef\xbb\xbftitle,severity\nXSS,high"
        result = await _parser().parse(csv)
        # BOM may be part of first header; parser still works
        assert result.stats.total_records_processed == 1

    async def test_latin1_replacement(self) -> None:
        # Invalid UTF-8 bytes handled with errors="replace"
        csv = b"title\n\xff\xfeInvalid"
        result = await _parser().parse(csv)
        assert result.stats.total_records_processed == 1


# ---------------------------------------------------------------------------
# _get_cell static method
# ---------------------------------------------------------------------------


class TestGetCell:
    @pytest.mark.parametrize(
        "row,index,expected",
        [
            (["a", "b", "c"], 0, "a"),
            (["a", "b", "c"], 2, "c"),
            (["  padded  "], 0, "padded"),
            (["a"], None, ""),
            (["a"], 5, ""),
            ([], 0, ""),
        ],
        ids=["first", "last", "stripped", "none-index", "out-of-range", "empty-row"],
    )
    def test_get_cell(self, row: list[str], index: int | None, expected: str) -> None:
        assert GenericCsvParser._get_cell(row, index) == expected
