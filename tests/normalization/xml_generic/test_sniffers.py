"""Tests for updated _classify_xml with Nessus/OpenVAS/Burp detection."""

from __future__ import annotations

from nocturna_engine.normalization.detector._sniffers import _classify_xml
from nocturna_engine.normalization.detector._types import InputFormat


class TestClassifyXmlNessus:
    def test_nessus_root_element(self) -> None:
        data = b'<?xml version="1.0"?><NessusClientData_v2><Report name="x"></Report></NessusClientData_v2>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_GENERIC
        assert result.confidence >= 0.9
        assert "nessus" in result.method

    def test_nessus_tool_hint(self) -> None:
        result = _classify_xml(b"<NessusClientData_v2></NessusClientData_v2>", tool_hint="nessus")
        assert result.format == InputFormat.XML_GENERIC
        assert result.tool_hint is not None
        assert "nessus" in result.tool_hint.lower()


class TestClassifyXmlOpenvas:
    def test_openvas_report_with_results(self) -> None:
        data = (
            b'<?xml version="1.0"?>'
            b'<report format_id="test"><results><result>'
            b"<name>v</name></result></results></report>"
        )
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_GENERIC
        assert "openvas" in result.method

    def test_openvas_tool_hint_detection(self) -> None:
        data = (
            b'<?xml version="1.0"?>'
            b'<report format_id="test"><results><result>'
            b"<name>v</name></result></results></report>"
        )
        result = _classify_xml(data, tool_hint="openvas")
        assert result.format == InputFormat.XML_GENERIC


class TestClassifyXmlBurp:
    def test_burp_issues_root(self) -> None:
        data = (
            b'<?xml version="1.0"?>'
            b"<issues><issue><name>SQLi</name></issue></issues>"
        )
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_GENERIC
        assert "burp" in result.method

    def test_burp_tool_hint(self) -> None:
        data = b"<issues><issue><name>x</name></issue></issues>"
        result = _classify_xml(data, tool_hint="burp")
        assert result.format == InputFormat.XML_GENERIC


class TestClassifyXmlNmapNotAffected:
    def test_nmap_still_detected_as_nmap(self) -> None:
        data = b'<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_NMAP

    def test_nmap_tool_hint(self) -> None:
        data = b"<something></something>"
        result = _classify_xml(data, tool_hint="nmap")
        assert result.format == InputFormat.XML_NMAP


class TestClassifyXmlGenericFallback:
    def test_unknown_xml_is_generic(self) -> None:
        data = b'<?xml version="1.0"?><custom_root><item>x</item></custom_root>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format == InputFormat.XML_GENERIC
        assert result.method == "xml_declaration_sniff"
