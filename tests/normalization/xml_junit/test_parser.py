"""Integration tests for JunitXmlParser.parse() — batch mode.

Covers: basic parsing, multiple suites, empty inputs, malformed XML,
bytes vs str, testcase counting, mixed pass/fail, tool-specific formats.
"""

from __future__ import annotations

import pytest

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers.xml_junit import JunitXmlParser

from tests.normalization.xml_junit.conftest import (
    bandit_testcase,
    checkov_testcase,
    junit_failure,
    junit_error,
    make_parser,
    passed_testcase,
    junit_testcase,
    junit_testsuite,
    trivy_testcase,
    wrap_junit,
    wrap_junit_single_suite,
)


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------


class TestBasicParsing:
    """Fundamental parse scenarios."""

    async def test_single_failure_produces_one_finding(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="test.Vuln",
                name="SQL Injection found",
                children_xml=junit_failure("Details here", message="Vuln detected"),
            ),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1
        assert result.findings[0].title == "SQL Injection found"

    async def test_single_error_produces_one_finding(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="test.Err",
                name="Runtime error in scan",
                children_xml=junit_error("Stack trace here", message="Error occurred"),
            ),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1
        assert result.findings[0].title == "Runtime error in scan"

    async def test_passed_testcase_skipped(self) -> None:
        xml = wrap_junit_single_suite(passed_testcase())
        result = await make_parser().parse(xml)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 1

    async def test_mixed_pass_and_fail(self) -> None:
        cases = (
            junit_testcase(
                classname="vuln.HIGH",
                name="CVE-2024-0001",
                children_xml=junit_failure("vuln details"),
            )
            + passed_testcase()
            + passed_testcase(name="another_pass")
            + junit_testcase(
                classname="vuln.LOW",
                name="CVE-2024-0002",
                children_xml=junit_failure("another vuln"),
            )
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert len(result.findings) == 2
        assert result.stats.records_skipped == 2
        assert result.stats.total_records_processed == 4
        assert result.stats.findings_produced == 2

    async def test_bytes_input(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Test vuln",
                children_xml=junit_failure("Details"),
            ),
        )
        result = await make_parser().parse(xml.encode("utf-8"))
        assert len(result.findings) == 1

    async def test_str_input(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Test vuln",
                children_xml=junit_failure("Details"),
            ),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1

    async def test_tool_name_propagated(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser(tool_name="trivy").parse(xml)
        assert result.findings[0].tool == "trivy"


# ---------------------------------------------------------------------------
# Multiple testsuites
# ---------------------------------------------------------------------------


class TestMultipleSuites:
    """Parsing documents with multiple <testsuite> elements."""

    async def test_two_suites_findings_combined(self) -> None:
        suite1 = junit_testsuite(
            junit_testcase(name="Vuln A", children_xml=junit_failure("A")),
            name="Suite 1",
        )
        suite2 = junit_testsuite(
            junit_testcase(name="Vuln B", children_xml=junit_failure("B")),
            name="Suite 2",
        )
        xml = wrap_junit(suite1 + suite2)
        result = await make_parser().parse(xml)
        assert len(result.findings) == 2

    async def test_testsuite_name_in_evidence(self) -> None:
        xml = wrap_junit(
            junit_testsuite(
                junit_testcase(name="Vuln", children_xml=junit_failure("text")),
                name="My Custom Suite",
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["testsuite_name"] == "My Custom Suite"

    async def test_standalone_testsuite_no_testsuites_root(self) -> None:
        """A <testsuite> without <testsuites> wrapper is valid JUnit XML."""
        xml = (
            '<?xml version="1.0"?>'
            '<testsuite name="Standalone" tests="1" failures="1">'
            '<testcase classname="test" name="Vuln">'
            '<failure message="fail">Details</failure>'
            '</testcase>'
            '</testsuite>'
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Empty and minimal inputs
# ---------------------------------------------------------------------------


class TestEmptyInputs:
    """Edge cases with empty or minimal data."""

    async def test_empty_testsuites(self) -> None:
        xml = wrap_junit("")
        result = await make_parser().parse(xml)
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0

    async def test_empty_testsuite(self) -> None:
        xml = wrap_junit_single_suite("")
        result = await make_parser().parse(xml)
        assert len(result.findings) == 0

    async def test_empty_string(self) -> None:
        result = await make_parser().parse("")
        assert len(result.issues) >= 1
        assert result.stats.errors_encountered >= 1

    async def test_empty_bytes(self) -> None:
        result = await make_parser().parse(b"")
        assert len(result.issues) >= 1

    async def test_only_passed_tests(self) -> None:
        cases = passed_testcase() + passed_testcase(name="p2") + passed_testcase(name="p3")
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 3
        assert result.stats.total_records_processed == 3


# ---------------------------------------------------------------------------
# Malformed XML
# ---------------------------------------------------------------------------


class TestMalformedXml:
    """Parser resilience against broken/invalid XML."""

    async def test_invalid_xml_produces_issue(self) -> None:
        result = await make_parser().parse("<not valid xml<<<>>>")
        assert len(result.issues) >= 1
        assert result.stats.errors_encountered >= 1
        assert "XML parse error" in result.issues[0].message

    async def test_truncated_xml(self) -> None:
        xml = '<?xml version="1.0"?><testsuites><testsuite name="t"><testcase'
        result = await make_parser().parse(xml)
        assert len(result.issues) >= 1

    async def test_unclosed_failure_tag(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase classname="c" name="n">'
            '<failure message="m">text'
            # Missing closing tags
        )
        result = await make_parser().parse(xml)
        assert len(result.issues) >= 1

    async def test_non_xml_content(self) -> None:
        result = await make_parser().parse("This is plain text, not XML at all.")
        assert len(result.issues) >= 1

    async def test_binary_garbage(self) -> None:
        result = await make_parser().parse(b"\x00\x01\x02\xff\xfe")
        assert len(result.issues) >= 1


# ---------------------------------------------------------------------------
# Testcase attributes
# ---------------------------------------------------------------------------


class TestTestcaseAttributes:
    """Edge cases in testcase attribute handling."""

    async def test_missing_classname_attr(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase name="Vuln found">'
            '<failure message="fail">text</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1
        assert result.findings[0].evidence["classname"] == ""

    async def test_missing_name_attr_uses_classname(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase classname="my.Class">'
            '<failure message="fail">text</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1
        # name is empty, so title falls back to classname
        assert result.findings[0].title == "my.Class"

    async def test_missing_both_name_and_classname(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase>'
            '<failure message="fail">some description text</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1
        assert result.findings[0].title == "Unknown test case"

    async def test_title_truncated_to_200(self) -> None:
        long_name = "A" * 300
        xml = wrap_junit_single_suite(
            junit_testcase(
                name=long_name,
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings[0].title) <= 200

    async def test_failure_message_attr_in_evidence(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("body", message="Check failed"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_message"] == "Check failed"

    async def test_failure_type_attr_in_evidence(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("body", failure_type="policy_violation"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_type"] == "policy_violation"


# ---------------------------------------------------------------------------
# Description handling
# ---------------------------------------------------------------------------


class TestDescriptionHandling:
    """Description field edge cases."""

    async def test_description_from_failure_text(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("Detailed vulnerability description here"),
            ),
        )
        result = await make_parser().parse(xml)
        assert "Detailed vulnerability description" in result.findings[0].description

    async def test_description_falls_back_to_message(self) -> None:
        """When failure text is empty, description should use message attr."""
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("", message="HIGH vulnerability found"),
            ),
        )
        result = await make_parser().parse(xml)
        assert "HIGH vulnerability found" in result.findings[0].description

    async def test_description_falls_back_to_title(self) -> None:
        """When both text and message are very short, fallback to title."""
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="SQL Injection detected",
                children_xml=junit_failure("", message=""),
            ),
        )
        result = await make_parser().parse(xml)
        assert "SQL Injection detected" in result.findings[0].description

    async def test_multiline_failure_text_preserved(self) -> None:
        text = "Line 1\nLine 2\nLine 3"
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure(text),
            ),
        )
        result = await make_parser().parse(xml)
        assert "Line 1" in result.findings[0].description
        assert "Line 3" in result.findings[0].description

    async def test_whitespace_stripped_in_failure_text(self) -> None:
        text = "\n\n   Actual content   \n\n"
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure(text),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].description == "Actual content"


# ---------------------------------------------------------------------------
# Tool-specific formats
# ---------------------------------------------------------------------------


class TestToolSpecificFormats:
    """Realistic tool output from Trivy, Checkov, Bandit."""

    async def test_trivy_format(self) -> None:
        xml = wrap_junit_single_suite(
            trivy_testcase(
                cve="CVE-2024-1234",
                package="libcurl",
                severity="HIGH",
                fixed_version="7.88.1",
                installed_version="7.68.0",
            ),
        )
        result = await make_parser(tool_name="trivy").parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == SeverityLevel.HIGH
        assert f.tool == "trivy"
        assert "CVE-2024-1234" in f.evidence.get("cves", [])

    async def test_checkov_format(self) -> None:
        xml = wrap_junit_single_suite(
            checkov_testcase(
                check_id="CKV_AWS_123",
                check_name="Ensure S3 encryption",
                resource="aws_s3_bucket.data",
                file_path="/main.tf",
                line=15,
            ),
        )
        result = await make_parser(tool_name="checkov").parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.title == "Ensure S3 encryption"
        assert f.target == "aws_s3_bucket.data"

    async def test_bandit_with_cwe(self) -> None:
        xml = wrap_junit_single_suite(
            bandit_testcase(
                issue_id="B101",
                description="Assert used",
                severity="MEDIUM",
                file_path="/app/main.py",
                line=42,
                cwe="CWE-703",
            ),
        )
        result = await make_parser(tool_name="bandit").parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.cwe == "CWE-703"

    async def test_mixed_tools_in_single_document(self) -> None:
        """Multiple tool outputs combined in one JUnit XML."""
        cases = (
            trivy_testcase("CVE-2024-0001", "openssl", "CRITICAL")
            + checkov_testcase("CKV_AWS_1", "Check 1", "aws_ec2.web", "/infra.tf")
            + passed_testcase()
            + bandit_testcase("B102", "Exec used", "HIGH", "/app/run.py")
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert len(result.findings) == 3
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------


class TestStats:
    """NormalizationStats correctness."""

    async def test_processed_count(self) -> None:
        cases = (
            junit_testcase(name="Fail One", children_xml=junit_failure("a"))
            + junit_testcase(name="Fail Two", children_xml=junit_failure("b"))
            + passed_testcase()
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert result.stats.total_records_processed == 3

    async def test_findings_produced_count(self) -> None:
        cases = (
            junit_testcase(name="Fail One", children_xml=junit_failure("a"))
            + junit_testcase(name="Fail Two", children_xml=junit_failure("b"))
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert result.stats.findings_produced == 2

    async def test_skipped_count(self) -> None:
        cases = passed_testcase() + passed_testcase(name="p2")
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert result.stats.records_skipped == 2

    async def test_errors_on_malformed(self) -> None:
        result = await make_parser().parse("<broken xml")
        assert result.stats.errors_encountered >= 1

    async def test_zero_issues_on_valid_input(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        assert len(result.issues) == 0


# ---------------------------------------------------------------------------
# Class attributes
# ---------------------------------------------------------------------------


class TestClassAttributes:
    def test_parser_name(self) -> None:
        assert JunitXmlParser.parser_name == "xml_junit"

    def test_source_format(self) -> None:
        assert JunitXmlParser.source_format == "xml_junit"
