"""Tests for evidence dict structure and CVE/CWE extraction in findings.

Covers: evidence keys, classname/failure_type/failure_message/testsuite_name,
CVE/CWE list in evidence, CWE in finding.cwe field, fingerprint stability.
"""

from __future__ import annotations

import pytest

from tests.normalization.xml_junit.conftest import (
    junit_failure,
    junit_error,
    make_parser,
    junit_testcase,
    junit_testsuite,
    trivy_testcase,
    wrap_junit,
    wrap_junit_single_suite,
)


# ---------------------------------------------------------------------------
# Evidence dict structure
# ---------------------------------------------------------------------------


class TestEvidenceStructure:
    """Evidence dict always has the required keys."""

    async def test_required_keys_present(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("body", message="msg", failure_type="vuln_type"),
            ),
        )
        result = await make_parser().parse(xml)
        ev = result.findings[0].evidence
        assert "classname" in ev
        assert "failure_type" in ev
        assert "failure_message" in ev
        assert "testsuite_name" in ev

    async def test_classname_value(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="trivy.HIGH",
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["classname"] == "trivy.HIGH"

    async def test_failure_type_value(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("text", failure_type="policy_violation"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_type"] == "policy_violation"

    async def test_failure_message_value(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("text", message="Check failed"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_message"] == "Check failed"

    async def test_testsuite_name_value(self) -> None:
        xml = wrap_junit(
            junit_testsuite(
                junit_testcase(name="Vuln", children_xml=junit_failure("text")),
                name="My Suite",
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["testsuite_name"] == "My Suite"

    async def test_empty_classname(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase name="Vuln">'
            '<failure>text</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["classname"] == ""

    async def test_error_element_type_defaults_to_error(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_error("stack trace"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_type"] == "error"

    async def test_failure_element_type_defaults_to_failure(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_type"] == "failure"


# ---------------------------------------------------------------------------
# CVE in evidence
# ---------------------------------------------------------------------------


class TestCveInEvidence:
    """CVE identifiers extracted into evidence['cves']."""

    async def test_single_cve(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("CVE: CVE-2024-1234"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence.get("cves") == ["CVE-2024-1234"]

    async def test_multiple_cves(self) -> None:
        text = "Vulnerable to CVE-2024-0001 and CVE-2023-99999"
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure(text)),
        )
        result = await make_parser().parse(xml)
        cves = result.findings[0].evidence.get("cves", [])
        assert "CVE-2024-0001" in cves
        assert "CVE-2023-99999" in cves

    async def test_cve_from_classname(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="CVE-2024-5678.check",
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        assert "CVE-2024-5678" in result.findings[0].evidence.get("cves", [])

    async def test_no_cves_key_absent(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("No CVEs here"),
            ),
        )
        result = await make_parser().parse(xml)
        assert "cves" not in result.findings[0].evidence

    async def test_cves_sorted(self) -> None:
        text = "CVE-2024-9999 CVE-2024-0001 CVE-2023-1234"
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure(text)),
        )
        result = await make_parser().parse(xml)
        cves = result.findings[0].evidence["cves"]
        assert cves == sorted(cves)

    async def test_cves_deduplicated(self) -> None:
        text = "CVE-2024-1234 again CVE-2024-1234"
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure(text)),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["cves"] == ["CVE-2024-1234"]


# ---------------------------------------------------------------------------
# CWE in evidence and finding.cwe
# ---------------------------------------------------------------------------


class TestCweInEvidence:
    """CWE identifiers extracted into evidence['cwes'] and finding.cwe."""

    async def test_single_cwe_in_evidence(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("CWE-79 detected"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence.get("cwes") == ["CWE-79"]

    async def test_cwe_set_on_finding(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("CWE-89 SQL injection"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].cwe == "CWE-89"

    async def test_first_cwe_used_on_finding(self) -> None:
        """When multiple CWEs found, the first (sorted) is used."""
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("CWE-89 and CWE-22"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].cwe == "CWE-22"  # sorted first

    async def test_no_cwes_key_absent(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("No CWEs")),
        )
        result = await make_parser().parse(xml)
        assert "cwes" not in result.findings[0].evidence
        assert result.findings[0].cwe is None

    async def test_cwe_from_classname(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="CWE-79.xss",
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].cwe == "CWE-79"

    async def test_cwe_from_message(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("text", message="CWE-352 CSRF detected"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].cwe == "CWE-352"


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


class TestFingerprint:
    """Finding fingerprint is generated and stable."""

    async def test_fingerprint_present(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].fingerprint
        assert len(result.findings[0].fingerprint) == 64  # SHA-256 hex

    async def test_fingerprint_stable(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        parser = make_parser()
        r1 = await parser.parse(xml)
        r2 = await parser.parse(xml)
        assert r1.findings[0].fingerprint == r2.findings[0].fingerprint

    async def test_different_findings_different_fingerprints(self) -> None:
        cases = (
            junit_testcase(classname="a", name="Vuln A", children_xml=junit_failure("a"))
            + junit_testcase(classname="b", name="Vuln B", children_xml=junit_failure("b"))
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        fp1 = result.findings[0].fingerprint
        fp2 = result.findings[1].fingerprint
        assert fp1 != fp2
