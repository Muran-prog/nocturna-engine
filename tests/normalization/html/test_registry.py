"""Tests for HTML parser registration and lookup in the global registry."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.registry import get_global_registry
from nocturna_engine.normalization.parsers.html import HtmlParser


# ---------------------------------------------------------------------------
# HTML parser registered in global registry
# ---------------------------------------------------------------------------


class TestHtmlParserRegistered:
    """HtmlParser is auto-registered and discoverable via the global registry."""

    def test_html_parser_in_list_parsers(self) -> None:
        registry = get_global_registry()
        names = [entry["name"] for entry in registry.list_parsers()]
        assert "html" in names

    def test_lookup_by_format(self) -> None:
        registry = get_global_registry()
        assert registry.lookup(InputFormat.HTML) is HtmlParser

    def test_lookup_by_name(self) -> None:
        registry = get_global_registry()
        assert registry.lookup_by_name("html") is HtmlParser

    @pytest.mark.parametrize(
        "tool_hint",
        [
            "nikto",
            "zap",
            "burp",
            "arachni",
            "wapiti",
        ],
    )
    def test_lookup_with_known_tool_hint(self, tool_hint: str) -> None:
        registry = get_global_registry()
        assert registry.lookup(InputFormat.HTML, tool_hint=tool_hint) is HtmlParser

    def test_lookup_with_unknown_tool_hint(self) -> None:
        registry = get_global_registry()
        assert registry.lookup(InputFormat.HTML, tool_hint="unknown_tool") is HtmlParser


# ---------------------------------------------------------------------------
# HTML parser metadata
# ---------------------------------------------------------------------------


class TestHtmlParserMetadata:
    """HtmlParser class-level metadata is correct."""

    def test_parser_name(self) -> None:
        assert HtmlParser.parser_name == "html"

    def test_source_format(self) -> None:
        assert HtmlParser.source_format == "html"

    def test_list_parsers_entry_has_correct_qualname(self) -> None:
        registry = get_global_registry()
        entries = registry.list_parsers()
        html_entries = [e for e in entries if e["name"] == "html"]
        assert len(html_entries) == 1
        assert html_entries[0]["class"] == HtmlParser.__qualname__
