"""Edge-case focused tests for the HTML table handler and extraction logic."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.parsers.html._table_extractor._handler import (
    _ExtractedTable,
    _HtmlTableHandler,
)


# ---------------------------------------------------------------------------
# _ExtractedTable construction
# ---------------------------------------------------------------------------


class TestExtractedTable:
    """Basic construction and slot behaviour of _ExtractedTable."""

    def test_construction_stores_headers_and_rows(self) -> None:
        table = _ExtractedTable(headers=["a", "b"], rows=[["1", "2"]])
        assert table.headers == ["a", "b"]
        assert table.rows == [["1", "2"]]

    def test_empty_construction(self) -> None:
        table = _ExtractedTable(headers=[], rows=[])
        assert table.headers == []
        assert table.rows == []

    def test_slots_defined(self) -> None:
        assert "__slots__" in dir(_ExtractedTable) or hasattr(_ExtractedTable, "__slots__")
        table = _ExtractedTable(headers=["h"], rows=[])
        with pytest.raises(AttributeError):
            table.nonexistent = "boom"  # type: ignore[attr-defined]

    def test_multiple_rows(self) -> None:
        rows = [["a", "b"], ["c", "d"], ["e", "f"]]
        table = _ExtractedTable(headers=["h1", "h2"], rows=rows)
        assert len(table.rows) == 3


# ---------------------------------------------------------------------------
# Table detection via handler.feed()
# ---------------------------------------------------------------------------


class TestTableDetection:
    """Test that feeding HTML to the handler collects security tables."""

    def test_security_table_detected(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "<tr><td>XSS</td><td>High</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 1
        assert handler.tables[0].headers == ["vulnerability", "severity"]
        assert handler.tables[0].rows == [["XSS", "High"]]

    def test_non_security_table_ignored(self) -> None:
        html = (
            "<table>"
            "<tr><th>Product</th><th>Price</th></tr>"
            "<tr><td>Widget</td><td>$10</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0

    def test_multiple_tables_detected(self) -> None:
        html = (
            "<table>"
            "<tr><th>Name</th><th>Risk</th><th>URL</th></tr>"
            "<tr><td>Bug1</td><td>High</td><td>http://a</td></tr>"
            "</table>"
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "<tr><td>Bug2</td><td>Low</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 2

    def test_table_without_data_rows_not_collected(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0


# ---------------------------------------------------------------------------
# Header detection heuristics
# ---------------------------------------------------------------------------


class TestHeaderDetection:
    """Test _is_header_row() and _is_security_table() static methods."""

    def test_security_keywords_detected(self) -> None:
        cells = ["Vulnerability", "Severity", "Target"]
        assert _HtmlTableHandler._is_header_row(cells) is True

    def test_two_keywords_minimum(self) -> None:
        """Two security keywords in a row should be detected as header."""
        cells = ["Vulnerability", "Severity"]
        assert _HtmlTableHandler._is_header_row(cells) is True

    def test_single_keyword_rejected(self) -> None:
        cells = ["Vulnerability", "Unrelated"]
        assert _HtmlTableHandler._is_header_row(cells) is False

    def test_no_keywords_rejected(self) -> None:
        cells = ["Product", "Price", "Quantity"]
        assert _HtmlTableHandler._is_header_row(cells) is False

    def test_case_insensitive_matching(self) -> None:
        cells = ["VULNERABILITY", "SEVERITY"]
        assert _HtmlTableHandler._is_header_row(cells) is True

    def test_partial_keyword_matching(self) -> None:
        cells = ["vulnerability_name", "severity_level"]
        assert _HtmlTableHandler._is_header_row(cells) is True

    def test_is_security_table_with_enough_keywords(self) -> None:
        headers = ["vulnerability", "severity", "target"]
        assert _HtmlTableHandler._is_security_table(headers) is True

    def test_is_security_table_with_insufficient_keywords(self) -> None:
        headers = ["vulnerability", "banana"]
        assert _HtmlTableHandler._is_security_table(headers) is False

    @pytest.mark.parametrize(
        "cells",
        [
            ["host", "risk"],
            ["url", "description"],
            ["cwe", "cvss"],
            ["alert", "confidence"],
            ["name", "severity"],
            ["target", "impact"],
        ],
        ids=["host-risk", "url-desc", "cwe-cvss", "alert-conf", "name-sev", "target-impact"],
    )
    def test_various_keyword_pairs_accepted(self, cells: list[str]) -> None:
        assert _HtmlTableHandler._is_header_row(cells) is True


# ---------------------------------------------------------------------------
# Script/style content filtering
# ---------------------------------------------------------------------------


class TestScriptStyleFiltering:
    """Script and style tag content must be excluded from extraction."""

    def test_script_content_not_in_text_chunks(self) -> None:
        html = '<script>var x = "vulnerability";</script><p>Hello world</p>'
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        combined = " ".join(handler.all_text_chunks)
        assert "vulnerability" not in combined.lower() or "Hello world" in combined
        assert "var x" not in combined

    def test_script_table_not_extracted(self) -> None:
        html = (
            "<script>"
            "<table><tr><th>Vulnerability</th><th>Severity</th></tr>"
            "<tr><td>XSS</td><td>High</td></tr></table>"
            "</script>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0

    def test_style_content_excluded_from_text(self) -> None:
        html = "<style>.risk { color: red; }</style><p>Visible</p>"
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        combined = " ".join(handler.all_text_chunks)
        assert ".risk" not in combined
        assert "color" not in combined
        assert "Visible" in combined

    def test_style_does_not_create_table(self) -> None:
        html = (
            "<style>"
            "table.vulnerability { border: 1px; }"
            ".severity { font-weight: bold; }"
            "</style>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0

    def test_real_table_after_script_still_detected(self) -> None:
        html = (
            '<script>var vuln = "test";</script>'
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "<tr><td>XSS</td><td>High</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 1


# ---------------------------------------------------------------------------
# Nested tables
# ---------------------------------------------------------------------------


class TestNestedTables:
    """Tables inside tables should be handled gracefully."""

    def test_nested_tables_extracted_separately(self) -> None:
        html = (
            "<table>"
            "<tr><th>Name</th><th>Risk</th><th>URL</th></tr>"
            "<tr><td>Outer</td><td>High</td><td>http://a</td></tr>"
            "<tr><td>"
            "  <table>"
            "  <tr><th>Vulnerability</th><th>Severity</th></tr>"
            "  <tr><td>Inner</td><td>Low</td></tr>"
            "  </table>"
            "</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        # Inner and outer tables may both or individually be captured;
        # key is no crash and at least one table found.
        assert len(handler.tables) >= 1


# ---------------------------------------------------------------------------
# Malformed HTML
# ---------------------------------------------------------------------------


class TestMalformedHtml:
    """Handler must not crash on malformed HTML."""

    def test_unclosed_table_tag(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "<tr><td>XSS</td><td>High</td></tr>"
            # No </table>
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        # Should not raise; table may or may not be collected.
        assert isinstance(handler.tables, list)

    def test_missing_tr_close(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th>"
            "<tr><td>XSS</td><td>High</td>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert isinstance(handler.tables, list)

    def test_completely_broken_html(self) -> None:
        html = "<<<not html at all>>>"
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0

    def test_empty_string(self) -> None:
        handler = _HtmlTableHandler()
        handler.feed("")
        handler.close()
        assert len(handler.tables) == 0


# ---------------------------------------------------------------------------
# all_text_chunks
# ---------------------------------------------------------------------------


class TestAllTextChunks:
    """Handler collects visible text for fallback extraction."""

    def test_text_collected_from_paragraphs(self) -> None:
        html = "<p>Hello</p><p>World</p>"
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert "Hello" in handler.all_text_chunks
        assert "World" in handler.all_text_chunks

    def test_whitespace_only_not_collected(self) -> None:
        html = "<p>   </p><p>Real</p>"
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert "Real" in handler.all_text_chunks
        for chunk in handler.all_text_chunks:
            assert chunk.strip() != ""

    def test_text_inside_table_cells_collected(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "<tr><td>XSS Bug</td><td>High</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        combined = " ".join(handler.all_text_chunks)
        assert "XSS Bug" in combined


# ---------------------------------------------------------------------------
# Max limits
# ---------------------------------------------------------------------------


class TestMaxLimits:
    """Tables/rows beyond limits are ignored."""

    def test_tables_beyond_max_ignored(self) -> None:
        from nocturna_engine.normalization.parsers.html._constants import _MAX_TABLES

        # Build _MAX_TABLES + 1 security tables.
        tables_html = ""
        for i in range(_MAX_TABLES + 1):
            tables_html += (
                "<table>"
                f"<tr><th>Vulnerability</th><th>Severity</th></tr>"
                f"<tr><td>Bug{i}</td><td>High</td></tr>"
                "</table>"
            )
        handler = _HtmlTableHandler()
        handler.feed(tables_html)
        handler.close()
        assert len(handler.tables) <= _MAX_TABLES

    def test_rows_beyond_max_ignored(self) -> None:
        from nocturna_engine.normalization.parsers.html._constants import _MAX_ROWS_PER_TABLE

        rows_html = ""
        for i in range(_MAX_ROWS_PER_TABLE + 5):
            rows_html += f"<tr><td>Bug{i}</td><td>High</td></tr>"
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            f"{rows_html}"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 1
        assert len(handler.tables[0].rows) <= _MAX_ROWS_PER_TABLE


# ---------------------------------------------------------------------------
# <thead> / <tbody>
# ---------------------------------------------------------------------------


class TestTheadTbody:
    """<thead> always treated as header, <tbody> rows are data."""

    def test_thead_used_as_headers(self) -> None:
        html = (
            "<table>"
            "<thead><tr><th>Vulnerability</th><th>Severity</th></tr></thead>"
            "<tbody><tr><td>XSS</td><td>High</td></tr></tbody>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 1
        assert handler.tables[0].headers == ["vulnerability", "severity"]
        assert handler.tables[0].rows == [["XSS", "High"]]

    def test_thead_with_td_cells(self) -> None:
        html = (
            "<table>"
            "<thead><tr><td>Vulnerability</td><td>Severity</td></tr></thead>"
            "<tbody><tr><td>Bug</td><td>Low</td></tr></tbody>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        # thead row treated as header even with <td> tags.
        assert len(handler.tables) == 1

    def test_tbody_rows_without_thead(self) -> None:
        html = (
            "<table>"
            "<tr><th>Name</th><th>Risk</th></tr>"
            "<tbody><tr><td>Bug</td><td>Medium</td></tr></tbody>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 1
        assert handler.tables[0].rows == [["Bug", "Medium"]]


# ---------------------------------------------------------------------------
# Empty tables
# ---------------------------------------------------------------------------


class TestEmptyTable:
    """Tables with no rows or header only are not collected."""

    def test_table_with_no_rows(self) -> None:
        html = "<table></table>"
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0

    def test_header_only_table(self) -> None:
        html = (
            "<table>"
            "<tr><th>Vulnerability</th><th>Severity</th></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0


# ---------------------------------------------------------------------------
# Table with no recognized headers
# ---------------------------------------------------------------------------


class TestTableWithNoHeaders:
    """Data rows without a detected header row are not collected."""

    def test_data_only_rows_no_table(self) -> None:
        html = (
            "<table>"
            "<tr><td>foo</td><td>bar</td></tr>"
            "<tr><td>baz</td><td>qux</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0

    def test_th_but_non_security_keywords(self) -> None:
        html = (
            "<table>"
            "<tr><th>Color</th><th>Shape</th></tr>"
            "<tr><td>Red</td><td>Circle</td></tr>"
            "</table>"
        )
        handler = _HtmlTableHandler()
        handler.feed(html)
        handler.close()
        assert len(handler.tables) == 0
