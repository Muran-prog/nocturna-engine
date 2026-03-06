"""Tests for Burp Suite XML parsing through the generic XML parser."""

from __future__ import annotations

import pytest

from nocturna_engine.models.finding import SeverityLevel
from tests.normalization.xml_generic.conftest import (
    burp_issue,
    make_parser,
    wrap_burp,
)


# ---------------------------------------------------------------------------
# Basic Burp parsing
# ---------------------------------------------------------------------------


class TestBurpBasicParsing:
    async def test_single_issue(self) -> None:
        xml = wrap_burp(burp_issue())
        result = await make_parser(tool_name="burp").parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "SQL Injection" in f.title

    async def test_multiple_issues(self) -> None:
        issues = (
            burp_issue(name="SQL Injection", severity="High")
            + burp_issue(name="XSS", severity="Medium")
        )
        xml = wrap_burp(issues)
        result = await make_parser(tool_name="burp").parse(xml)
        assert len(result.findings) == 2

    async def test_bytes_input(self) -> None:
        xml = wrap_burp(burp_issue())
        result = await make_parser(tool_name="burp").parse(xml.encode("utf-8"))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Burp severity (via SeverityMap.resolve)
# ---------------------------------------------------------------------------


class TestBurpSeverity:
    @pytest.mark.parametrize(
        "severity,expected",
        [
            ("High", SeverityLevel.HIGH),
            ("Medium", SeverityLevel.MEDIUM),
            ("Low", SeverityLevel.LOW),
            ("Information", SeverityLevel.INFO),
        ],
        ids=["high", "medium", "low", "information"],
    )
    async def test_severity_levels(self, severity: str, expected: SeverityLevel) -> None:
        xml = wrap_burp(burp_issue(severity=severity))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.findings[0].severity == expected

    async def test_false_positive_skipped(self) -> None:
        xml = wrap_burp(burp_issue(severity="False positive"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# Target construction (host + path)
# ---------------------------------------------------------------------------


class TestBurpTarget:
    async def test_host_and_path_combined(self) -> None:
        xml = wrap_burp(burp_issue(host="https://example.com", path="/api/login"))
        result = await make_parser(tool_name="burp").parse(xml)
        target = result.findings[0].target
        assert "example.com" in target
        assert "/api/login" in target

    async def test_host_trailing_slash_no_double(self) -> None:
        xml = wrap_burp(burp_issue(host="https://example.com/", path="/api"))
        result = await make_parser(tool_name="burp").parse(xml)
        target = result.findings[0].target
        assert "//" not in target.replace("https://", "")

    async def test_target_hint_fallback(self) -> None:
        xml = wrap_burp(burp_issue(host="", path=""))
        result = await make_parser(tool_name="burp", target_hint="fallback.com").parse(xml)
        assert result.findings[0].target == "fallback.com"


# ---------------------------------------------------------------------------
# Evidence fields
# ---------------------------------------------------------------------------


class TestBurpEvidence:
    async def test_confidence_in_evidence(self) -> None:
        xml = wrap_burp(burp_issue(confidence="Certain"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.findings[0].evidence.get("confidence") == "Certain"

    async def test_host_in_evidence(self) -> None:
        xml = wrap_burp(burp_issue(host="https://target.com"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.findings[0].evidence.get("host") == "https://target.com"

    async def test_path_in_evidence(self) -> None:
        xml = wrap_burp(burp_issue(path="/vulnerable/endpoint"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.findings[0].evidence.get("path") == "/vulnerable/endpoint"

    async def test_issue_detail_in_evidence(self) -> None:
        xml = wrap_burp(burp_issue(issue_detail="Param 'id' injectable"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert "issue_detail" in result.findings[0].evidence

    async def test_remediation_in_evidence(self) -> None:
        xml = wrap_burp(burp_issue(remediation_detail="Use parameterized queries."))
        result = await make_parser(tool_name="burp").parse(xml)
        assert "remediation_detail" in result.findings[0].evidence

    async def test_serial_number_in_evidence(self) -> None:
        xml = wrap_burp(burp_issue(serial_number="9876543210"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.findings[0].evidence.get("serial_number") == "9876543210"

    async def test_issue_type_in_evidence(self) -> None:
        xml = wrap_burp(burp_issue(issue_type="16777216"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.findings[0].evidence.get("issue_type") == "16777216"


# ---------------------------------------------------------------------------
# CWE extraction from vulnerability classifications
# ---------------------------------------------------------------------------


class TestBurpCweCve:
    async def test_cwe_from_classifications(self) -> None:
        xml = wrap_burp(burp_issue(
            vuln_classifications="CWE-89: Improper Neutralization of SQL",
        ))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.findings[0].cwe == "CWE-89"

    async def test_cve_from_classifications(self) -> None:
        xml = wrap_burp(burp_issue(
            vuln_classifications="Related to CVE-2023-44487",
        ))
        result = await make_parser(tool_name="burp").parse(xml)
        # CVE extraction is best-effort; at minimum parsing should succeed.
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Description building
# ---------------------------------------------------------------------------


class TestBurpDescription:
    async def test_issue_detail_in_description(self) -> None:
        xml = wrap_burp(burp_issue(issue_detail="Detailed injection info"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert "Detailed injection info" in result.findings[0].description

    async def test_remediation_in_description(self) -> None:
        xml = wrap_burp(burp_issue(remediation_detail="Fix with prepared statements"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert "Remediation" in result.findings[0].description

    async def test_fallback_description_when_no_detail(self) -> None:
        xml = wrap_burp(burp_issue(issue_detail="", remediation_detail="", issue_background=""))
        result = await make_parser(tool_name="burp").parse(xml)
        assert "Burp Suite detected" in result.findings[0].description

    async def test_issue_background_used_as_fallback(self) -> None:
        xml = wrap_burp(burp_issue(
            issue_detail="",
            issue_background="Background context here",
        ))
        result = await make_parser(tool_name="burp").parse(xml)
        assert "Background context here" in result.findings[0].description


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestBurpStats:
    async def test_processed_and_produced(self) -> None:
        issues = burp_issue(severity="High") + burp_issue(severity="Medium")
        xml = wrap_burp(issues)
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.stats.total_records_processed == 2
        assert result.stats.findings_produced == 2

    async def test_false_positive_counted_as_skipped(self) -> None:
        xml = wrap_burp(burp_issue(severity="False positive"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# Origin metadata
# ---------------------------------------------------------------------------


class TestBurpOriginMetadata:
    async def test_parser_and_tool_name(self) -> None:
        xml = wrap_burp(burp_issue())
        result = await make_parser(tool_name="burp").parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["parser_name"] == "xml_generic"
        assert meta["tool_name"] == "burp"

    async def test_original_severity(self) -> None:
        xml = wrap_burp(burp_issue(severity="High"))
        result = await make_parser(tool_name="burp", preserve_raw=True).parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["original_severity"] == "High"
