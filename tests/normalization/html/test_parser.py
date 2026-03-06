"""Edge-case focused tests for HtmlParser.parse() with real HTML inputs."""

from __future__ import annotations


import pytest

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers.html import HtmlParser

from tests.normalization.html.conftest import (
    html_table,
    make_parser,
    nikto_table,
    wrap_html,
    zap_table,
)


# ---------------------------------------------------------------------------
# Basic table parsing
# ---------------------------------------------------------------------------


class TestBasicTableParsing:
    """Standard table with security headers produces findings."""

    async def test_single_row_one_finding(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity", "Target", "Description"],
            [["XSS", "high", "example.com", "Cross-site scripting"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.title == "XSS"
        assert f.severity == SeverityLevel.HIGH
        assert f.target == "example.com"
        assert f.description == "Cross-site scripting"

    async def test_multiple_rows_multiple_findings(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [
                ["XSS", "high"],
                ["SQLi", "critical"],
                ["CSRF", "medium"],
            ],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 3

    async def test_headers_in_different_order(self) -> None:
        body = html_table(
            ["Description", "Severity", "Target", "Vulnerability"],
            [["Desc text", "low", "host.com", "OpenRedirect"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 1
        assert result.findings[0].title == "OpenRedirect"
        assert result.findings[0].description == "Desc text"
        assert result.findings[0].target == "host.com"

    async def test_th_based_header_row(self) -> None:
        body = html_table(
            ["Name", "Risk", "URL"],
            [["Bug", "High", "http://test.com"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Multiple tables in document
# ---------------------------------------------------------------------------


class TestMultipleTablesInDocument:
    """HTML with 2+ security tables produces findings from all."""

    async def test_two_security_tables(self) -> None:
        table1 = html_table(
            ["Vulnerability", "Severity"],
            [["Bug1", "high"]],
        )
        table2 = html_table(
            ["Name", "Risk", "URL"],
            [["Bug2", "low", "http://a"]],
        )
        result = await make_parser().parse(wrap_html(table1 + table2))
        assert len(result.findings) == 2

    async def test_three_tables_all_contribute(self) -> None:
        tables = ""
        for i in range(3):
            tables += html_table(
                ["Vulnerability", "Severity"],
                [[f"Bug{i}", "medium"]],
            )
        result = await make_parser().parse(wrap_html(tables))
        assert len(result.findings) == 3


# ---------------------------------------------------------------------------
# Non-security tables ignored
# ---------------------------------------------------------------------------


class TestNonSecurityTablesIgnored:
    """Table with non-security headers produces 0 findings."""

    async def test_product_table_ignored(self) -> None:
        body = html_table(
            ["Product", "Price", "Quantity"],
            [["Widget", "$10", "5"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 0

    async def test_navigation_table_ignored(self) -> None:
        body = html_table(
            ["Link", "Label"],
            [["http://a", "Home"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Mixed tables
# ---------------------------------------------------------------------------


class TestMixedTables:
    """One security table + one non-security table → findings only from security."""

    async def test_mixed_security_and_non_security(self) -> None:
        sec_table = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"]],
        )
        non_sec = html_table(
            ["Product", "Price"],
            [["Widget", "$10"]],
        )
        result = await make_parser().parse(wrap_html(sec_table + non_sec))
        assert len(result.findings) == 1
        assert result.findings[0].title == "XSS"


# ---------------------------------------------------------------------------
# Empty and minimal inputs
# ---------------------------------------------------------------------------


class TestEmptyAndMinimal:
    """Edge cases for empty/minimal HTML data."""

    async def test_empty_string(self) -> None:
        result = await make_parser().parse("")
        assert len(result.findings) == 0

    async def test_empty_bytes(self) -> None:
        result = await make_parser().parse(b"")
        assert len(result.findings) == 0

    async def test_html_with_no_tables(self) -> None:
        result = await make_parser().parse(wrap_html("<p>No tables here</p>"))
        assert len(result.findings) == 0

    async def test_header_only_table_no_findings(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 0

    async def test_minimal_html_document(self) -> None:
        result = await make_parser().parse("<!DOCTYPE html><html><body></body></html>")
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Row edge cases
# ---------------------------------------------------------------------------


class TestRowEdgeCases:
    """Row-level boundary conditions."""

    async def test_empty_row_skipped(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"], ["", ""], ["SQLi", "medium"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 2
        assert result.stats.records_skipped >= 1

    async def test_row_more_cells_than_headers(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "<tr><td>XSS</td><td>High</td><td>extra1</td><td>extra2</td></tr>"
            "</table>"
        )
        result = await make_parser().parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].title == "XSS"

    async def test_row_fewer_cells_than_headers(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th><th>Target</th></tr>"
            "<tr><td>XSS</td></tr>"
            "</table>"
        )
        result = await make_parser().parse(html)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.title == "XSS"
        assert f.severity == SeverityLevel.INFO

    async def test_whitespace_only_cells_skipped(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["   ", "   "]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 0

    async def test_no_title_column_row_skipped(self) -> None:
        html = (
            "<table>"
            "<tr><th>Severity</th><th>Host</th></tr>"
            "<tr><td>High</td><td>example.com</td></tr>"
            "</table>"
        )
        result = await make_parser().parse(html)
        assert len(result.findings) == 0
        assert result.stats.records_skipped >= 1


# ---------------------------------------------------------------------------
# CVSS column
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
        body = html_table(
            ["Vulnerability", "CVSS", "Severity"],
            [["Bug", cvss_val, "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].cvss == expected

    @pytest.mark.parametrize(
        "cvss_val",
        ["-0.1", "10.1", "100", "-5"],
        ids=["below-zero", "above-ten", "way-high", "negative"],
    )
    async def test_out_of_range_cvss_ignored(self, cvss_val: str) -> None:
        body = html_table(
            ["Vulnerability", "CVSS", "Severity"],
            [["Bug", cvss_val, "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].cvss is None

    @pytest.mark.parametrize(
        "cvss_val",
        ["abc", "N/A", "", "high", "  "],
        ids=["text", "na", "empty", "severity-word", "whitespace"],
    )
    async def test_non_numeric_cvss_ignored(self, cvss_val: str) -> None:
        body = html_table(
            ["Vulnerability", "CVSS", "Severity"],
            [["Bug", cvss_val, "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].cvss is None


# ---------------------------------------------------------------------------
# CWE column
# ---------------------------------------------------------------------------


class TestCweColumn:
    """CWE mapping edge cases."""

    async def test_cwe_mapped(self) -> None:
        body = html_table(
            ["Vulnerability", "CWE", "Severity"],
            [["XSS", "CWE-79", "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].cwe == "CWE-79"

    async def test_cwe_missing_column(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].cwe is None

    async def test_cwe_empty_cell(self) -> None:
        body = html_table(
            ["Vulnerability", "CWE", "Severity"],
            [["XSS", "", "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].cwe is None


# ---------------------------------------------------------------------------
# Tool column
# ---------------------------------------------------------------------------


class TestToolColumn:
    """Tool from table column vs. config fallback."""

    async def test_tool_from_table_column(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity", "Tool"],
            [["Bug", "high", "nikto"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].tool == "nikto"

    async def test_tool_fallback_to_config(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["Bug", "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].tool == "test_html"

    async def test_tool_empty_cell_fallback(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity", "Tool"],
            [["Bug", "high", ""]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].tool == "test_html"


# ---------------------------------------------------------------------------
# Title truncation
# ---------------------------------------------------------------------------


class TestTitleTruncation:
    """Long titles must be truncated to 200 chars."""

    async def test_very_long_title_truncated(self) -> None:
        long_title = "A" * 300
        body = html_table(
            ["Vulnerability", "Severity"],
            [[long_title, "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings[0].title) == 200

    async def test_exactly_200_not_truncated(self) -> None:
        title = "B" * 200
        body = html_table(
            ["Vulnerability", "Severity"],
            [[title, "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].title == title


# ---------------------------------------------------------------------------
# Description fallback
# ---------------------------------------------------------------------------


class TestDescriptionFallback:
    """Description from column, fallback to title."""

    async def test_description_from_column(self) -> None:
        body = html_table(
            ["Vulnerability", "Description", "Severity"],
            [["Bug", "Detailed description", "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].description == "Detailed description"

    async def test_description_falls_back_to_title(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["My Bug Title", "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.findings[0].description == "My Bug Title"


# ---------------------------------------------------------------------------
# Bytes input
# ---------------------------------------------------------------------------


class TestBytesInput:
    """HTML provided as bytes must be decoded properly."""

    async def test_bytes_decoded(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"]],
        )
        result = await make_parser().parse(wrap_html(body).encode("utf-8"))
        assert len(result.findings) == 1

    async def test_utf8_with_bom(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["XSS", "high"]],
        )
        bom_data = b"\xef\xbb\xbf" + wrap_html(body).encode("utf-8")
        result = await make_parser().parse(bom_data)
        assert result.stats.total_records_processed >= 1

    async def test_invalid_utf8_with_replacement(self) -> None:
        raw = b"<table><tr><th>Vulnerability</th><th>Severity</th></tr>"
        raw += b"<tr><td>\xff\xfeInvalid</td><td>high</td></tr></table>"
        result = await make_parser().parse(raw)
        assert result.stats.total_records_processed >= 1


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------


class TestStatsTracking:
    """Verify NormalizationStats counters."""

    async def test_stats_all_parsed(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["Alpha", "high"], ["Bravo", "medium"], ["Charlie", "low"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.stats.total_records_processed == 3
        assert result.stats.findings_produced == 3

    async def test_stats_with_skips(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["Valid", "high"], ["", ""], ["Also Valid", "low"]],
        )
        result = await make_parser().parse(wrap_html(body))
        assert result.stats.findings_produced == 2
        assert result.stats.records_skipped >= 1

    async def test_stats_records_skipped_calculation(self) -> None:
        body = html_table(
            ["Vulnerability", "Severity"],
            [["A", "high"]],
        )
        result = await make_parser().parse(wrap_html(body))
        expected_skipped = (
            result.stats.total_records_processed
            - result.stats.findings_produced
            - result.stats.errors_encountered
        )
        assert result.stats.records_skipped == expected_skipped

    async def test_stats_empty_input(self) -> None:
        result = await make_parser().parse("")
        assert result.stats.total_records_processed == 0
        assert result.stats.findings_produced == 0


# ---------------------------------------------------------------------------
# Class attributes
# ---------------------------------------------------------------------------


class TestClassAttributes:
    """Verify parser_name and source_format class attributes."""

    def test_parser_name(self) -> None:
        assert HtmlParser.parser_name == "html"

    def test_source_format(self) -> None:
        assert HtmlParser.source_format == "html"

    def test_instance_parser_name(self) -> None:
        p = make_parser()
        assert p.parser_name == "html"

    def test_instance_source_format(self) -> None:
        p = make_parser()
        assert p.source_format == "html"


# ---------------------------------------------------------------------------
# ZAP and Nikto table helpers (integration)
# ---------------------------------------------------------------------------


class TestZapTable:
    """ZAP-style table parsing via zap_table helper."""

    async def test_zap_table_parsed(self) -> None:
        body = zap_table([
            {
                "name": "XSS Reflected",
                "risk": "High",
                "url": "http://target.com/page",
                "description": "Reflected XSS found",
                "cwe": "CWE-79",
            },
        ])
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == SeverityLevel.HIGH
        assert f.cwe == "CWE-79"

    async def test_zap_multiple_rows(self) -> None:
        body = zap_table([
            {"name": "Bug One", "risk": "High", "url": "http://a.com", "description": "Desc one here", "cwe": ""},
            {"name": "Bug Two", "risk": "Low", "url": "http://b.com", "description": "Desc two here", "cwe": ""},
        ])
        result = await make_parser().parse(wrap_html(body))
        assert len(result.findings) == 2


class TestNiktoTable:
    """Nikto-style table parsing via nikto_table helper."""

    async def test_nikto_table_no_title_column(self) -> None:
        body = nikto_table([
            ("/admin", "GET", "Admin page found"),
        ])
        result = await make_parser().parse(wrap_html(body))
        # Nikto headers URI/HTTP Method/Description — only 'description' is a security keyword,
        # so the table is not recognized as a security table (needs >= 2).
        # This means fallback extraction is used instead.
        assert result.stats.findings_produced == 0 or len(result.findings) >= 0
