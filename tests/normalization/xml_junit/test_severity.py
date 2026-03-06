"""Tests for severity extraction and mapping in JUnit XML parser.

Covers: classname-based severity, message-based, text-body-based,
priority chain, SeverityMap integration, default MEDIUM fallback.
"""

from __future__ import annotations

import pytest

from nocturna_engine.models.finding import SeverityLevel

from tests.normalization.xml_junit.conftest import (
    junit_failure,
    make_parser,
    junit_testcase,
    wrap_junit_single_suite,
)


# ---------------------------------------------------------------------------
# Severity from classname
# ---------------------------------------------------------------------------


class TestSeverityFromClassname:
    """Severity extraction from the classname attribute."""

    @pytest.mark.parametrize(
        "classname,expected",
        [
            ("trivy.CRITICAL", SeverityLevel.CRITICAL),
            ("trivy.HIGH", SeverityLevel.HIGH),
            ("scanner.MEDIUM", SeverityLevel.MEDIUM),
            ("tool.LOW", SeverityLevel.LOW),
            ("audit.INFO", SeverityLevel.INFO),
        ],
        ids=["critical", "high", "medium", "low", "info"],
    )
    async def test_severity_levels(
        self,
        classname: str,
        expected: SeverityLevel,
    ) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname=classname,
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == expected

    async def test_case_insensitive_classname(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="trivy.high",
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# Severity from failure message attribute
# ---------------------------------------------------------------------------


class TestSeverityFromMessage:
    """Severity extraction from failure message attribute."""

    @pytest.mark.parametrize(
        "message,expected",
        [
            ("CRITICAL vulnerability", SeverityLevel.CRITICAL),
            ("HIGH severity issue", SeverityLevel.HIGH),
            ("MEDIUM risk detected", SeverityLevel.MEDIUM),
            ("LOW priority finding", SeverityLevel.LOW),
            ("INFO: informational notice", SeverityLevel.INFO),
        ],
        ids=["critical", "high", "medium", "low", "info"],
    )
    async def test_severity_from_message(
        self,
        message: str,
        expected: SeverityLevel,
    ) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="no.match.here",
                name="Vuln",
                children_xml=junit_failure("text", message=message),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == expected


# ---------------------------------------------------------------------------
# Severity from failure text body
# ---------------------------------------------------------------------------


class TestSeverityFromTextBody:
    """Severity extraction from failure text content."""

    async def test_severity_in_text_body(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="no.match",
                name="Vuln",
                children_xml=junit_failure(
                    "Severity: CRITICAL\nPackage: lib",
                    message="no match",
                ),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.CRITICAL

    async def test_severity_keyword_anywhere_in_text(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="no.match",
                name="Vuln",
                children_xml=junit_failure(
                    "This is a HIGH risk vulnerability in production",
                    message="no match",
                ),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# Priority chain
# ---------------------------------------------------------------------------


class TestSeverityPriority:
    """Classname > message > text priority chain."""

    async def test_classname_beats_message(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="trivy.CRITICAL",
                name="Vuln",
                children_xml=junit_failure("text", message="LOW issue"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.CRITICAL

    async def test_classname_beats_text(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="tool.HIGH",
                name="Vuln",
                children_xml=junit_failure("This is CRITICAL severity"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.HIGH

    async def test_message_beats_text(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="no.match",
                name="Vuln",
                children_xml=junit_failure(
                    "CRITICAL in body",
                    message="HIGH alert",
                ),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# Default fallback
# ---------------------------------------------------------------------------


class TestSeverityDefault:
    """Default MEDIUM when no severity keyword found."""

    async def test_default_medium_no_keyword(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="com.example.Test",
                name="Some check failed",
                children_xml=junit_failure(
                    "No severity keyword here at all",
                    message="Check failed",
                ),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.MEDIUM

    async def test_default_medium_empty_classname_and_message(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase name="Vuln">'
            '<failure>plain text only</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.MEDIUM


# ---------------------------------------------------------------------------
# INFORMATIONAL keyword
# ---------------------------------------------------------------------------


class TestInformationalSeverity:
    """The INFORMATIONAL keyword maps to INFO."""

    async def test_informational_maps_to_info(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="tool.INFORMATIONAL",
                name="Notice",
                children_xml=junit_failure("advisory"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].severity == SeverityLevel.INFO
