"""Tests for JUnit XML format detection and hint resolution.

Covers: _classify_xml sniffing, _resolve_hint aliases, confidence levels,
priority against other XML formats, edge cases.
"""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.detector._hints import _resolve_hint
from nocturna_engine.normalization.detector._sniffers import _classify_xml, _sniff_structure
from nocturna_engine.normalization.detector._types import DetectionResult, InputFormat


# ---------------------------------------------------------------------------
# _classify_xml sniffing
# ---------------------------------------------------------------------------


class TestClassifyXmlJunit:
    """JUnit XML detection in _classify_xml."""

    def test_testsuites_root_detected(self) -> None:
        data = b'<?xml version="1.0"?><testsuites><testsuite name="s"></testsuite></testsuites>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_JUNIT
        assert result.confidence == 0.9
        assert result.method == "xml_junit_element_sniff"

    def test_testsuite_root_detected(self) -> None:
        data = b'<?xml version="1.0"?><testsuite name="s" tests="1"></testsuite>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_JUNIT
        assert result.confidence == 0.9

    def test_detection_case_insensitive(self) -> None:
        """The sniffer lowercases the first 2048 bytes."""
        data = b'<?xml version="1.0"?><TESTSUITES><TESTSUITE name="s"></TESTSUITE></TESTSUITES>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_JUNIT

    def test_tool_hint_preserved(self) -> None:
        data = b'<?xml version="1.0"?><testsuites></testsuites>'
        result = _classify_xml(data, tool_hint="trivy")
        assert result.tool_hint == "trivy"

    def test_tool_hint_none_stays_none(self) -> None:
        data = b'<?xml version="1.0"?><testsuites></testsuites>'
        result = _classify_xml(data, tool_hint=None)
        assert result.tool_hint is None

    def test_nmap_takes_priority_over_junit(self) -> None:
        """If nmaprun is present, nmap detection should win (it's checked earlier)."""
        data = b'<?xml version="1.0"?><nmaprun scanner="nmap"><testsuite></testsuite></nmaprun>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_NMAP

    def test_junit_not_confused_with_nessus(self) -> None:
        data = b'<?xml version="1.0"?><NessusClientData><testsuite></testsuite></NessusClientData>'
        result = _classify_xml(data, tool_hint=None)
        # Nessus detection is before JUnit in the chain
        assert result.format in (InputFormat.XML_GENERIC, InputFormat.XML_JUNIT)

    def test_generic_xml_without_junit_elements(self) -> None:
        data = b'<?xml version="1.0"?><root><item>data</item></root>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_GENERIC

    def test_testsuite_element_deep_in_document(self) -> None:
        """testsuite appearing within the first 2048 bytes should be detected."""
        prefix = b'<?xml version="1.0"?><testsuites>' + b" " * 100
        data = prefix + b"<testsuite></testsuite></testsuites>"
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_JUNIT


# ---------------------------------------------------------------------------
# _sniff_structure integration
# ---------------------------------------------------------------------------


class TestSniffStructureJunit:
    """JUnit detection through the main _sniff_structure entry point."""

    def test_xml_junit_via_sniff_structure(self) -> None:
        data = b'<?xml version="1.0"?><testsuites><testsuite></testsuite></testsuites>'
        result = _sniff_structure(data, tool_hint=None)
        assert result is not None
        assert result.format == InputFormat.XML_JUNIT

    def test_bare_xml_junit_no_declaration(self) -> None:
        """XML without declaration but starting with '<' still routes to _classify_xml."""
        data = b"<testsuites><testsuite></testsuite></testsuites>"
        result = _sniff_structure(data, tool_hint=None)
        assert result is not None
        assert result.format == InputFormat.XML_JUNIT


# ---------------------------------------------------------------------------
# Hint resolution
# ---------------------------------------------------------------------------


class TestHintResolution:
    """_resolve_hint aliases for JUnit XML."""

    @pytest.mark.parametrize(
        "hint",
        ["junit", "junit_xml", "xunit", "xml_junit"],
        ids=["junit", "junit_xml", "xunit", "xml_junit"],
    )
    def test_hint_resolves_to_xml_junit(self, hint: str) -> None:
        assert _resolve_hint(hint) == InputFormat.XML_JUNIT

    @pytest.mark.parametrize(
        "hint",
        ["JUNIT", "JUnit", "JUNIT_XML", "JUnit-XML", "XUNIT", "XML_JUNIT"],
        ids=["JUNIT", "JUnit", "JUNIT_XML", "JUnit-XML", "XUNIT", "XML_JUNIT"],
    )
    def test_hint_case_insensitive(self, hint: str) -> None:
        assert _resolve_hint(hint) == InputFormat.XML_JUNIT

    def test_hint_with_dashes_normalized(self) -> None:
        assert _resolve_hint("junit-xml") == InputFormat.XML_JUNIT

    def test_hint_with_spaces_normalized(self) -> None:
        assert _resolve_hint("junit xml") == InputFormat.XML_JUNIT

    def test_unrelated_hint_not_junit(self) -> None:
        assert _resolve_hint("sarif") != InputFormat.XML_JUNIT

    def test_unknown_hint_returns_none(self) -> None:
        assert _resolve_hint("totally_unknown_format") is None
