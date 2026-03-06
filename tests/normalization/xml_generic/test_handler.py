"""Tests for SAX handler format detection and state machine."""

from __future__ import annotations

from io import BytesIO

from defusedxml import sax as defused_sax

from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import ParserConfig
from nocturna_engine.normalization.parsers.xml_generic.sax_handler import _GenericXmlSaxHandler
from nocturna_engine.normalization.severity import build_severity_map


def _make_handler() -> _GenericXmlSaxHandler:
    config = ParserConfig(tool_name="test", severity_map=build_severity_map())
    return _GenericXmlSaxHandler(
        config=config,
        stats=NormalizationStats(),
        severity_map=config.severity_map,
        preserve_raw=True,
    )


def _parse_xml(xml: str) -> _GenericXmlSaxHandler:
    handler = _make_handler()
    defused_sax.parse(BytesIO(xml.encode("utf-8")), handler)
    return handler


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


class TestFormatDetection:
    def test_nessus_detected(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '<Report name="x"><ReportHost name="h">'
            '<ReportItem pluginName="p" pluginID="1" severity="2" port="80" protocol="tcp">'
            "<description>d</description>"
            "</ReportItem>"
            "</ReportHost></Report>"
            "</NessusClientData_v2>"
        )
        handler = _parse_xml(xml)
        assert handler._format == "nessus"

    def test_burp_detected(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            "<issues>"
            "<issue><name>Test</name>"
            "<host>http://x</host>"
            "<path>/</path>"
            "<severity>High</severity>"
            "<confidence>Certain</confidence>"
            "</issue>"
            "</issues>"
        )
        handler = _parse_xml(xml)
        assert handler._format == "burp"

    def test_openvas_detected(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            '<report format_id="test">'
            "<results>"
            "<result>"
            "<name>Vuln</name>"
            "<host>10.0.0.1</host>"
            "<port>80/tcp</port>"
            "<threat>High</threat>"
            "<description>Desc</description>"
            "</result>"
            "</results>"
            "</report>"
        )
        handler = _parse_xml(xml)
        assert handler._format == "openvas"

    def test_unknown_root_falls_to_generic(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            "<custom_scanner>"
            "<vulnerability>"
            "<name>Vuln</name>"
            "<description>Desc</description>"
            "<host>x</host>"
            "</vulnerability>"
            "</custom_scanner>"
        )
        handler = _parse_xml(xml)
        assert handler._format == "generic"


# ---------------------------------------------------------------------------
# State machine: Nessus
# ---------------------------------------------------------------------------


class TestNessusStateMachine:
    def test_report_host_tracking(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '<Report name="x">'
            '<ReportHost name="192.168.1.1">'
            '<ReportItem pluginName="Apache HTTP" pluginID="1" severity="2" port="80" protocol="tcp">'
            "<description>Remote web server detected.</description>"
            "</ReportItem>"
            "</ReportHost>"
            "</Report>"
            "</NessusClientData_v2>"
        )
        handler = _parse_xml(xml)
        assert len(handler.findings) == 1
        assert handler.findings[0].target == "192.168.1.1"

    def test_multiple_items_in_host(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '<Report name="x">'
            '<ReportHost name="h">'
            '<ReportItem pluginName="Apache HTTP" pluginID="1" severity="2" port="80" protocol="tcp">'
            "<description>Remote web server detected.</description>"
            "</ReportItem>"
            '<ReportItem pluginName="OpenSSL Vuln" pluginID="2" severity="3" port="443" protocol="tcp">'
            "<description>SSL certificate issue found.</description>"
            "</ReportItem>"
            "</ReportHost>"
            "</Report>"
            "</NessusClientData_v2>"
        )
        handler = _parse_xml(xml)
        assert len(handler.findings) == 2


# ---------------------------------------------------------------------------
# State machine: Burp
# ---------------------------------------------------------------------------


class TestBurpStateMachine:
    def test_multiple_issues(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            "<issues>"
            "<issue>"
            "<name>SQLi</name><host>http://a</host><path>/</path>"
            "<severity>High</severity><confidence>Certain</confidence>"
            "</issue>"
            "<issue>"
            "<name>XSS</name><host>http://b</host><path>/x</path>"
            "<severity>Medium</severity><confidence>Firm</confidence>"
            "</issue>"
            "</issues>"
        )
        handler = _parse_xml(xml)
        assert len(handler.findings) == 2


# ---------------------------------------------------------------------------
# State machine: OpenVAS
# ---------------------------------------------------------------------------


class TestOpenvasStateMachine:
    def test_nvt_inside_result(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            '<report format_id="test">'
            "<results>"
            "<result>"
            "<name>Vuln</name>"
            "<host>10.0.0.1</host>"
            "<port>80/tcp</port>"
            "<threat>High</threat>"
            "<description>Desc</description>"
            '<nvt oid="1.2.3">'
            "<name>NVT Name</name>"
            "<cve>CVE-2024-1234</cve>"
            "<cvss_base>9.0</cvss_base>"
            "</nvt>"
            "</result>"
            "</results>"
            "</report>"
        )
        handler = _parse_xml(xml)
        assert len(handler.findings) == 1
        assert handler.findings[0].cvss == 9.0


# ---------------------------------------------------------------------------
# Issues tracking
# ---------------------------------------------------------------------------


class TestIssuesTracking:
    def test_no_issues_on_valid_xml(self) -> None:
        xml = (
            '<?xml version="1.0"?>'
            "<NessusClientData_v2>"
            '<Report name="x">'
            '<ReportHost name="h">'
            '<ReportItem pluginName="Test Plugin Name" pluginID="1" severity="2" port="80" protocol="tcp">'
            "<description>A valid test description here.</description>"
            "</ReportItem>"
            "</ReportHost>"
            "</Report>"
            "</NessusClientData_v2>"
        )
        handler = _parse_xml(xml)
        assert len(handler.issues) == 0
