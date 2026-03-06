"""Tests for OpenVAS XML parsing through the generic XML parser."""

from __future__ import annotations

import pytest

from nocturna_engine.models.finding import SeverityLevel
from tests.normalization.xml_generic.conftest import (
    make_parser,
    openvas_nvt,
    openvas_result,
    wrap_openvas,
)


# ---------------------------------------------------------------------------
# Basic OpenVAS parsing
# ---------------------------------------------------------------------------


class TestOpenvasBasicParsing:
    async def test_single_result(self) -> None:
        xml = wrap_openvas(openvas_result())
        result = await make_parser(tool_name="openvas").parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "Test Vulnerability" in f.title
        assert f.target == "10.0.0.1"

    async def test_multiple_results(self) -> None:
        results_xml = (
            openvas_result(name="Vuln A", threat="High")
            + openvas_result(name="Vuln B", threat="Low")
        )
        xml = wrap_openvas(results_xml)
        result = await make_parser(tool_name="openvas").parse(xml)
        assert len(result.findings) == 2

    async def test_bytes_input(self) -> None:
        xml = wrap_openvas(openvas_result())
        result = await make_parser(tool_name="openvas").parse(xml.encode("utf-8"))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# OpenVAS severity (via SeverityMap.resolve)
# ---------------------------------------------------------------------------


class TestOpenvasSeverity:
    @pytest.mark.parametrize(
        "threat,expected",
        [
            ("High", SeverityLevel.HIGH),
            ("Medium", SeverityLevel.MEDIUM),
            ("Low", SeverityLevel.LOW),
        ],
        ids=["high", "medium", "low"],
    )
    async def test_threat_levels(self, threat: str, expected: SeverityLevel) -> None:
        xml = wrap_openvas(openvas_result(threat=threat))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert result.findings[0].severity == expected

    async def test_log_skipped_when_empty_description(self) -> None:
        xml = wrap_openvas(openvas_result(threat="Log", description=""))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 1

    async def test_log_kept_when_has_description(self) -> None:
        xml = wrap_openvas(openvas_result(threat="Log", description="Informational data"))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert len(result.findings) == 1

    async def test_false_positive_skipped(self) -> None:
        xml = wrap_openvas(openvas_result(threat="False Positive", description=""))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# NVT data extraction
# ---------------------------------------------------------------------------


class TestOpenvasNvtData:
    async def test_cve_from_nvt(self) -> None:
        nvt = openvas_nvt(cve="CVE-2023-44487")
        xml = wrap_openvas(openvas_result(nvt_xml=nvt))
        result = await make_parser(tool_name="openvas").parse(xml)
        # Finding should be produced; CVE comes from nvt element.
        assert len(result.findings) == 1

    async def test_nocve_placeholder_ignored(self) -> None:
        nvt = openvas_nvt(cve="NOCVE")
        xml = wrap_openvas(openvas_result(nvt_xml=nvt))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert len(result.findings) == 1

    async def test_cvss_base_from_nvt(self) -> None:
        nvt = openvas_nvt(cvss_base="7.5")
        xml = wrap_openvas(openvas_result(nvt_xml=nvt))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert result.findings[0].cvss == 7.5

    async def test_nvt_oid_in_evidence(self) -> None:
        nvt = openvas_nvt(oid="1.3.6.1.4.1.25623.1.0.12345")
        xml = wrap_openvas(openvas_result(nvt_xml=nvt))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert result.findings[0].evidence.get("nvt_oid") == "1.3.6.1.4.1.25623.1.0.12345"

    async def test_solution_in_evidence(self) -> None:
        nvt = openvas_nvt(solution="Apply vendor patch.")
        xml = wrap_openvas(openvas_result(nvt_xml=nvt))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert "solution" in result.findings[0].evidence

    async def test_cwe_from_nvt_tags(self) -> None:
        nvt = openvas_nvt(tags="cvss_base_vector=AV:N|CWE-79|extra")
        xml = wrap_openvas(openvas_result(nvt_xml=nvt))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert result.findings[0].cwe == "CWE-79"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestOpenvasEvidence:
    async def test_port_in_evidence(self) -> None:
        xml = wrap_openvas(openvas_result(port="443/tcp"))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert result.findings[0].evidence.get("port") == "443/tcp"

    async def test_threat_in_evidence(self) -> None:
        xml = wrap_openvas(openvas_result(threat="High"))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert result.findings[0].evidence.get("threat") == "High"


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestOpenvasStats:
    async def test_processed_count(self) -> None:
        results_xml = openvas_result(threat="High") + openvas_result(threat="Low")
        xml = wrap_openvas(results_xml)
        result = await make_parser(tool_name="openvas").parse(xml)
        assert result.stats.total_records_processed == 2
        assert result.stats.findings_produced == 2


# ---------------------------------------------------------------------------
# Origin metadata
# ---------------------------------------------------------------------------


class TestOpenvasOriginMetadata:
    async def test_parser_and_tool_name(self) -> None:
        xml = wrap_openvas(openvas_result())
        result = await make_parser(tool_name="openvas").parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["parser_name"] == "xml_generic"
        assert meta["tool_name"] == "openvas"

    async def test_original_severity(self) -> None:
        xml = wrap_openvas(openvas_result(threat="High"))
        result = await make_parser(tool_name="openvas", preserve_raw=True).parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["original_severity"] == "High"
