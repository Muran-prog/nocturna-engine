"""Tests for generic fallback XML parsing through the generic XML parser."""

from __future__ import annotations

from nocturna_engine.models.finding import SeverityLevel
from tests.normalization.xml_generic.conftest import (
    generic_vuln,
    make_parser,
    wrap_generic,
)


# ---------------------------------------------------------------------------
# Basic generic parsing
# ---------------------------------------------------------------------------


class TestGenericBasicParsing:
    async def test_vulnerability_element(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={
                "name": "Test Vuln",
                "description": "A test vulnerability description.",
                "severity": "high",
                "host": "10.0.0.1",
            },
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "Test Vuln" in f.title
        assert f.target == "10.0.0.1"
        assert f.severity == SeverityLevel.HIGH

    async def test_finding_element(self) -> None:
        item = generic_vuln(
            tag="finding",
            children={
                "title": "Open Redirect",
                "description": "Open redirect found.",
                "severity": "medium",
                "url": "https://example.com/redirect",
            },
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert len(result.findings) == 1
        assert "Open Redirect" in result.findings[0].title

    async def test_issue_element(self) -> None:
        item = generic_vuln(
            tag="issue",
            children={
                "name": "Missing Header",
                "description": "X-Frame-Options missing.",
                "severity": "low",
                "host": "web.local",
            },
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert len(result.findings) == 1

    async def test_multiple_vulnerabilities(self) -> None:
        items = (
            generic_vuln(
                tag="vulnerability",
                children={"name": "Vuln A", "description": "Desc A", "severity": "high", "host": "a.com"},
            )
            + generic_vuln(
                tag="vulnerability",
                children={"name": "Vuln B", "description": "Desc B", "severity": "low", "host": "b.com"},
            )
        )
        xml = wrap_generic(items_xml=items)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert len(result.findings) == 2


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


class TestGenericTarget:
    async def test_host_field(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "host": "10.0.0.5"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].target == "10.0.0.5"

    async def test_target_field(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "target": "server.local"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].target == "server.local"

    async def test_ip_field(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "ip": "172.16.0.1"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].target == "172.16.0.1"

    async def test_url_field(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "url": "https://site.com/page"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].target == "https://site.com/page"

    async def test_target_hint_fallback(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner", target_hint="fallback.io").parse(xml)
        assert result.findings[0].target == "fallback.io"

    async def test_unknown_fallback(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].target == "unknown"


# ---------------------------------------------------------------------------
# Severity resolution
# ---------------------------------------------------------------------------


class TestGenericSeverity:
    async def test_severity_field(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "severity": "critical", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].severity == SeverityLevel.CRITICAL

    async def test_risk_field(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "risk": "medium", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].severity == SeverityLevel.MEDIUM

    async def test_missing_severity_defaults_to_info(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].severity == SeverityLevel.INFO


# ---------------------------------------------------------------------------
# CVE / CWE / CVSS
# ---------------------------------------------------------------------------


class TestGenericCveCweCvss:
    async def test_cve_from_child_element(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "cve": "CVE-2024-9999", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        # Best-effort; at minimum parsing should succeed.
        assert len(result.findings) == 1

    async def test_cwe_from_child_element(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "cwe": "CWE-79", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].cwe == "CWE-79"

    async def test_cvss_from_child_element(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "cvss": "8.1", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].cvss == 8.1


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestGenericEvidence:
    async def test_port_in_evidence(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "port": "8080", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].evidence.get("port") == "8080"

    async def test_source_element_in_evidence(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.findings[0].evidence.get("source_element") == "vulnerability"

    async def test_solution_in_evidence(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "description": "Desc", "solution": "Patch now", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert "solution" in result.findings[0].evidence


# ---------------------------------------------------------------------------
# Fallback title and description
# ---------------------------------------------------------------------------


class TestGenericFallbacks:
    async def test_title_from_name(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "My Vuln Name", "description": "Desc", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert "My Vuln Name" in result.findings[0].title

    async def test_title_fallback_when_no_name(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"description": "Desc only", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert "vulnerability" in result.findings[0].title.lower()

    async def test_description_fallback(self) -> None:
        item = generic_vuln(
            tag="vulnerability",
            children={"name": "Vuln", "host": "x"},
        )
        xml = wrap_generic(items_xml=item)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert "vulnerability" in result.findings[0].description.lower()


# ---------------------------------------------------------------------------
# Non-vuln element names are ignored
# ---------------------------------------------------------------------------


class TestGenericIgnoredElements:
    async def test_non_vuln_tag_ignored(self) -> None:
        xml = wrap_generic(items_xml="<config><setting>value</setting></config>")
        result = await make_parser(tool_name="scanner").parse(xml)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestGenericStats:
    async def test_processed_and_produced(self) -> None:
        items = (
            generic_vuln(tag="vulnerability", children={"name": "Vuln Alpha", "description": "Description Alpha", "host": "alpha.local"})
            + generic_vuln(tag="finding", children={"name": "Vuln Beta", "description": "Description Beta", "host": "beta.local"})
        )
        xml = wrap_generic(items_xml=items)
        result = await make_parser(tool_name="scanner").parse(xml)
        assert result.stats.total_records_processed == 2
        assert result.stats.findings_produced == 2
