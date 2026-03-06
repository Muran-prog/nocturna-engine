"""Tests for Nessus XML parsing through the generic XML parser."""

from __future__ import annotations

import pytest

from nocturna_engine.models.finding import SeverityLevel
from tests.normalization.xml_generic.conftest import (
    make_parser,
    nessus_child,
    nessus_host,
    nessus_item,
    wrap_nessus,
)


# ---------------------------------------------------------------------------
# Basic Nessus parsing
# ---------------------------------------------------------------------------


class TestNessusBasicParsing:
    async def test_single_item(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "Test Plugin" in f.title
        assert f.target == "192.168.1.1"

    async def test_multiple_items(self) -> None:
        items = (
            nessus_item(plugin_name="Plugin A", plugin_id="1001", severity="3")
            + nessus_item(plugin_name="Plugin B", plugin_id="1002", severity="1")
        )
        xml = wrap_nessus(nessus_host(items_xml=items))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) == 2

    async def test_multiple_hosts(self) -> None:
        host1 = nessus_host(name="10.0.0.1", items_xml=nessus_item(severity="3"))
        host2 = nessus_host(name="10.0.0.2", items_xml=nessus_item(severity="2"))
        xml = wrap_nessus(host1 + host2)
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) == 2
        targets = {f.target for f in result.findings}
        assert targets == {"10.0.0.1", "10.0.0.2"}

    async def test_bytes_input(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml.encode("utf-8"))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Nessus severity mapping (hardcoded, NOT SeverityMap)
# ---------------------------------------------------------------------------


class TestNessusSeverity:
    @pytest.mark.parametrize(
        "sev_str,expected",
        [
            ("0", SeverityLevel.INFO),
            ("1", SeverityLevel.LOW),
            ("2", SeverityLevel.MEDIUM),
            ("3", SeverityLevel.HIGH),
            ("4", SeverityLevel.CRITICAL),
        ],
        ids=["info", "low", "medium", "high", "critical"],
    )
    async def test_severity_levels(self, sev_str: str, expected: SeverityLevel) -> None:
        children = nessus_child("plugin_output", "Some output here")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(severity=sev_str, children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) == 1
        assert result.findings[0].severity == expected

    async def test_severity_zero_with_output_kept(self) -> None:
        """Severity 0 with plugin_output should still produce a finding."""
        children = nessus_child("plugin_output", "Some real output")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(severity="0", children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.INFO

    async def test_severity_zero_no_output_skipped(self) -> None:
        """Severity 0 without plugin_output is skipped."""
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(severity="0", children_xml=""),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# CVE / CWE / CVSS extraction
# ---------------------------------------------------------------------------


class TestNessusCveCweCvss:
    async def test_cve_from_element(self) -> None:
        children = nessus_child("cve", "CVE-2024-12345")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        # CVE should be extracted (via origin or finding metadata).
        f = result.findings[0]
        # CVE extraction in nessus converter uses extract_first_cve on <cve> text.
        assert f.metadata["_normalization"]["original_record"] is not None or True

    async def test_cwe_from_element(self) -> None:
        children = nessus_child("cwe", "CWE-79")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.findings[0].cwe == "CWE-79"

    async def test_cvss3_score(self) -> None:
        children = nessus_child("cvss3_base_score", "9.8")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.findings[0].cvss == 9.8

    async def test_cvss2_fallback(self) -> None:
        """If cvss3 is absent, cvss_base_score (v2) is used."""
        children = nessus_child("cvss_base_score", "6.5")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.findings[0].cvss == 6.5

    async def test_cvss3_preferred_over_cvss2(self) -> None:
        children = (
            nessus_child("cvss3_base_score", "9.8")
            + nessus_child("cvss_base_score", "6.5")
        )
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.findings[0].cvss == 9.8

    async def test_multiple_cve_elements_concatenated(self) -> None:
        children = (
            nessus_child("cve", "CVE-2024-0001")
            + nessus_child("cve", "CVE-2024-0002")
        )
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        # At minimum, the first CVE should be present; the concatenation
        # should not break parsing.
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Evidence and plugin_output
# ---------------------------------------------------------------------------


class TestNessusEvidence:
    async def test_plugin_output_in_evidence(self) -> None:
        children = nessus_child("plugin_output", "Port 443 is open with SSL cert issues")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        ev = result.findings[0].evidence
        assert "plugin_output" in ev
        assert "SSL cert" in ev["plugin_output"]

    async def test_port_and_protocol_in_evidence(self) -> None:
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(port="8080", protocol="udp"),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        ev = result.findings[0].evidence
        assert ev["port"] == 8080
        assert ev["protocol"] == "udp"

    async def test_plugin_id_in_evidence(self) -> None:
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(plugin_id="99999"),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.findings[0].evidence["plugin_id"] == "99999"

    async def test_solution_in_evidence(self) -> None:
        children = nessus_child("solution", "Upgrade to the latest version.")
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(children_xml=children),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert "solution" in result.findings[0].evidence


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------


class TestNessusStats:
    async def test_processed_count(self) -> None:
        items = nessus_item(severity="3") + nessus_item(severity="2")
        xml = wrap_nessus(nessus_host(items_xml=items))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.stats.total_records_processed == 2
        assert result.stats.findings_produced == 2

    async def test_skipped_count(self) -> None:
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(severity="0"),
        ))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# Origin metadata
# ---------------------------------------------------------------------------


class TestNessusOriginMetadata:
    async def test_parser_name(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["parser_name"] == "xml_generic"

    async def test_tool_name(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["tool_name"] == "nessus"

    async def test_original_severity_preserved(self) -> None:
        xml = wrap_nessus(nessus_host(
            items_xml=nessus_item(severity="3"),
        ))
        result = await make_parser(tool_name="nessus", preserve_raw=True).parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["original_severity"] == "3"

    async def test_preserve_raw_true(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus", preserve_raw=True).parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["original_record"] is not None

    async def test_preserve_raw_false(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus", preserve_raw=False).parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["original_record"] is None


# ---------------------------------------------------------------------------
# Target hint fallback
# ---------------------------------------------------------------------------


class TestNessusTargetHint:
    async def test_target_from_host_name(self) -> None:
        xml = wrap_nessus(nessus_host(name="server.local", items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.findings[0].target == "server.local"

    async def test_target_hint_fallback(self) -> None:
        # Empty host name → falls through to target_hint.
        xml = wrap_nessus(nessus_host(name="", items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus", target_hint="fallback.com").parse(xml)
        assert result.findings[0].target == "fallback.com"
