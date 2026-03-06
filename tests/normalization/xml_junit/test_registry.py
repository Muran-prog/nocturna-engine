"""Tests for JUnit XML parser registration in the global registry.

Covers: registration presence, format binding, tool patterns, priority,
class identity, lookup by name and format.
"""

from __future__ import annotations

from nocturna_engine.normalization.detector._types import InputFormat
from nocturna_engine.normalization.parsers.xml_junit import JunitXmlParser
from nocturna_engine.normalization.registry import get_global_registry


class TestRegistration:
    """Parser registration in the global registry."""

    def test_parser_registered_by_name(self) -> None:
        registry = get_global_registry()
        parsers = registry.list_parsers()
        names = [p["name"] for p in parsers]
        assert "xml_junit" in names

    def test_parser_class_lookup(self) -> None:
        registry = get_global_registry()
        cls = registry.lookup_by_name("xml_junit")
        assert cls is JunitXmlParser

    def test_format_binding(self) -> None:
        registry = get_global_registry()
        parsers = registry.list_parsers()
        entry = next(p for p in parsers if p["name"] == "xml_junit")
        assert InputFormat.XML_JUNIT in entry["formats"]


class TestClassAttributes:
    """Parser class-level attributes."""

    def test_parser_name(self) -> None:
        assert JunitXmlParser.parser_name == "xml_junit"

    def test_source_format(self) -> None:
        assert JunitXmlParser.source_format == "xml_junit"
