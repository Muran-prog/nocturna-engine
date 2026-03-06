"""Tests for _JunitSaxHandler edge cases.

Covers: multiple failure/error children, nested testsuite, error vs failure,
whitespace handling, large documents, encoding.
"""

from __future__ import annotations

import pytest

from nocturna_engine.models.finding import SeverityLevel

from tests.normalization.xml_junit.conftest import (
    junit_error,
    junit_failure,
    make_parser,
    passed_testcase,
    junit_testcase,
    junit_testsuite,
    wrap_junit,
    wrap_junit_single_suite,
)


# ---------------------------------------------------------------------------
# Failure vs error elements
# ---------------------------------------------------------------------------


class TestFailureVsError:
    """Both <failure> and <error> children produce findings."""

    async def test_failure_produces_finding(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("fail body")),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1

    async def test_error_produces_finding(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Err", children_xml=junit_error("error body")),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1

    async def test_error_type_attr_defaults_to_error(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Err", children_xml=junit_error("body")),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_type"] == "error"

    async def test_failure_type_attr_defaults_to_failure(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Failure test", children_xml=junit_failure("body")),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_type"] == "failure"

    async def test_custom_type_attr_preserved(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Failure test",
                children_xml=junit_failure("body", failure_type="custom_type"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].evidence["failure_type"] == "custom_type"


# ---------------------------------------------------------------------------
# Multiple failure/error in one testcase
# ---------------------------------------------------------------------------


class TestMultipleChildElements:
    """Testcase with multiple failure/error children."""

    async def test_last_failure_wins(self) -> None:
        """Only one finding per testcase, last failure/error provides text."""
        children = junit_failure("first fail") + junit_failure("second fail")
        xml = wrap_junit_single_suite(
            junit_testcase(name="Multi", children_xml=children),
        )
        result = await make_parser().parse(xml)
        # Should produce exactly one finding per testcase
        assert len(result.findings) == 1
        # The second failure text overwrites the first char buffer
        assert "second fail" in result.findings[0].description

    async def test_failure_then_error(self) -> None:
        children = junit_failure("fail") + junit_error("err")
        xml = wrap_junit_single_suite(
            junit_testcase(name="Mixed", children_xml=children),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Nested testsuites
# ---------------------------------------------------------------------------


class TestNestedTestsuites:
    """Nested <testsuite> elements (valid in JUnit XML)."""

    async def test_nested_suite_findings_collected(self) -> None:
        inner_suite = junit_testsuite(
            junit_testcase(name="Inner Vuln", children_xml=junit_failure("inner")),
            name="Inner Suite",
        )
        outer_suite = junit_testsuite(
            junit_testcase(name="Outer Vuln", children_xml=junit_failure("outer"))
            + inner_suite,
            name="Outer Suite",
        )
        xml = wrap_junit(outer_suite)
        result = await make_parser().parse(xml)
        assert len(result.findings) == 2

    async def test_inner_suite_name_propagated(self) -> None:
        """Inner suite name should override for testcases within it."""
        inner_suite = junit_testsuite(
            junit_testcase(name="Inner Vuln", children_xml=junit_failure("inner")),
            name="Inner Suite",
        )
        outer_suite = junit_testsuite(
            inner_suite,
            name="Outer Suite",
        )
        xml = wrap_junit(outer_suite)
        result = await make_parser().parse(xml)
        # The inner testsuite's name should be in evidence
        assert result.findings[0].evidence["testsuite_name"] == "Inner Suite"


# ---------------------------------------------------------------------------
# Whitespace handling
# ---------------------------------------------------------------------------


class TestWhitespaceHandling:
    """Whitespace in failure text and attributes."""

    async def test_leading_trailing_whitespace_stripped(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("\n\n  Content here  \n\n"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].description == "Content here"

    async def test_multiline_text_preserved(self) -> None:
        text = "Line 1\nLine 2\nLine 3"
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure(text)),
        )
        result = await make_parser().parse(xml)
        assert "Line 1" in result.findings[0].description
        assert "Line 3" in result.findings[0].description

    async def test_empty_failure_text_uses_message(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln",
                children_xml=junit_failure("", message="Fallback message"),
            ),
        )
        result = await make_parser().parse(xml)
        assert "Fallback message" in result.findings[0].description

    async def test_whitespace_only_failure_text_uses_fallback(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Vuln Title",
                children_xml=junit_failure("   \n\t  ", message=""),
            ),
        )
        result = await make_parser().parse(xml)
        assert "Vuln Title" in result.findings[0].description


# ---------------------------------------------------------------------------
# Large document
# ---------------------------------------------------------------------------


class TestLargeDocument:
    """Performance with many testcases."""

    async def test_100_failures(self) -> None:
        cases = "".join(
            junit_testcase(
                classname=f"cls.{i}",
                name=f"Vuln {i}",
                children_xml=junit_failure(f"Details for vuln {i}"),
            )
            for i in range(100)
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert len(result.findings) == 100
        assert result.stats.total_records_processed == 100
        assert result.stats.findings_produced == 100

    async def test_100_passed(self) -> None:
        cases = "".join(
            passed_testcase(name=f"pass_{i}") for i in range(100)
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert len(result.findings) == 0
        assert result.stats.records_skipped == 100

    async def test_mixed_500(self) -> None:
        cases = "".join(
            junit_testcase(
                name=f"Case {i}",
                children_xml=junit_failure(f"Fail {i}") if i % 2 == 0 else "",
            )
            if i % 2 == 0
            else passed_testcase(name=f"Pass {i}")
            for i in range(500)
        )
        xml = wrap_junit_single_suite(cases)
        result = await make_parser().parse(xml)
        assert result.stats.total_records_processed == 500
        assert result.stats.findings_produced == 250
        assert result.stats.records_skipped == 250


# ---------------------------------------------------------------------------
# Encoding edge cases
# ---------------------------------------------------------------------------


class TestEncoding:
    """XML encoding handling."""

    async def test_utf8_bom(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        bom_bytes = b"\xef\xbb\xbf" + xml.encode("utf-8")
        result = await make_parser().parse(bom_bytes)
        assert len(result.findings) == 1

    async def test_unicode_in_failure_text(self) -> None:
        text = "Уязвимость найдена в модуле 日本語テスト"
        xml = wrap_junit_single_suite(
            junit_testcase(name="Unicode Vuln", children_xml=junit_failure(text)),
        )
        result = await make_parser().parse(xml)
        assert len(result.findings) == 1
        assert "Уязвимость" in result.findings[0].description

    async def test_xml_entities_in_text(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                name="Entity test",
                children_xml=junit_failure("a &amp; b &lt; c &gt; d"),
            ),
        )
        result = await make_parser().parse(xml)
        assert "a & b < c > d" in result.findings[0].description


# ---------------------------------------------------------------------------
# XXE protection (batch mode)
# ---------------------------------------------------------------------------


class TestXxeProtection:
    """Batch parse blocks entity expansion attacks."""

    async def test_billion_laughs_blocked(self) -> None:
        from defusedxml import EntitiesForbidden

        payload = (
            '<?xml version="1.0"?>'
            "<!DOCTYPE z ["
            '  <!ENTITY a "AAAAAAAAAA">'
            '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            "]>"
            "<testsuites><testsuite>"
            '<testcase classname="c" name="n">'
            "<failure>&c;</failure>"
            "</testcase></testsuite></testsuites>"
        )
        with pytest.raises(EntitiesForbidden):
            await make_parser().parse(payload)

    async def test_external_entity_blocked(self) -> None:
        from defusedxml import EntitiesForbidden

        payload = (
            '<?xml version="1.0"?>'
            "<!DOCTYPE z ["
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
            "]>"
            "<testsuites><testsuite>"
            '<testcase classname="c" name="n">'
            "<failure>&xxe;</failure>"
            "</testcase></testsuite></testsuites>"
        )
        with pytest.raises(EntitiesForbidden):
            await make_parser().parse(payload)
