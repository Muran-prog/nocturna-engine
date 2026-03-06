"""Tests for target extraction in JUnit XML parser.

Covers: URL extraction, Resource: line, file paths, classname fallback,
target_hint fallback, unknown fallback, priority chain.
"""

from __future__ import annotations

import pytest

from tests.normalization.xml_junit.conftest import (
    junit_failure,
    make_parser,
    junit_testcase,
    wrap_junit_single_suite,
)


# ---------------------------------------------------------------------------
# URL target
# ---------------------------------------------------------------------------


class TestUrlTarget:
    """URL extraction from failure text."""

    async def test_https_url(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("Affected: https://example.com/api/v1"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "https://example.com/api/v1"

    async def test_http_url(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("See http://internal.corp/vuln"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "http://internal.corp/vuln"

    async def test_url_with_query_params(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("https://example.com/api?key=val&amp;foo=bar"),
            ),
        )
        result = await make_parser().parse(xml)
        assert "example.com" in result.findings[0].target

    async def test_url_takes_priority_over_resource(self) -> None:
        text = "https://example.com\nResource: aws_s3.bucket"
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure(text),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "https://example.com"


# ---------------------------------------------------------------------------
# Resource: target
# ---------------------------------------------------------------------------


class TestResourceTarget:
    """Resource: line extraction from failure text."""

    async def test_resource_line(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("Resource: aws_s3_bucket.data\nFile: /main.tf:15"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "aws_s3_bucket.data"

    async def test_resource_case_insensitive(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("resource: my_resource.name"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "my_resource.name"

    async def test_resource_whitespace_stripped(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("Resource:    aws_iam_role.admin   "),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "aws_iam_role.admin"


# ---------------------------------------------------------------------------
# File path target
# ---------------------------------------------------------------------------


class TestFilePathTarget:
    """File path extraction from failure text."""

    async def test_file_path_with_line(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("Issue in /src/main.py:42"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "/src/main.py:42"

    async def test_file_path_without_line(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("Config: /etc/config.yaml"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "/etc/config.yaml"

    async def test_nested_path(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("Found in /a/b/c/d/e.tf:100"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "/a/b/c/d/e.tf:100"


# ---------------------------------------------------------------------------
# Classname fallback
# ---------------------------------------------------------------------------


class TestClassnameFallback:
    """Classname used as target when no URL/Resource/path found."""

    async def test_classname_as_target(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="com.example.SecurityCheck",
                name="Vuln",
                children_xml=junit_failure("No target patterns here"),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "com.example.SecurityCheck"


# ---------------------------------------------------------------------------
# target_hint fallback
# ---------------------------------------------------------------------------


class TestTargetHintFallback:
    """target_hint from ParserConfig used when no other target found."""

    async def test_target_hint_used(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase name="Vuln">'
            '<failure>No target patterns here</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser(target_hint="fallback.host").parse(xml)
        assert result.findings[0].target == "fallback.host"


# ---------------------------------------------------------------------------
# Unknown fallback
# ---------------------------------------------------------------------------


class TestUnknownFallback:
    """'unknown' used when no target info available at all."""

    async def test_unknown_when_nothing_available(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase name="Vuln">'
            '<failure>No patterns and no classname</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "unknown"


# ---------------------------------------------------------------------------
# Priority chain integration
# ---------------------------------------------------------------------------


class TestTargetPriorityChain:
    """Full priority chain: URL > Resource > path > classname > hint > unknown."""

    async def test_url_beats_all(self) -> None:
        text = "https://example.com\nResource: res\n/path/file:1"
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure(text),
            ),
        )
        result = await make_parser(target_hint="hint").parse(xml)
        assert result.findings[0].target == "https://example.com"

    async def test_resource_beats_path(self) -> None:
        text = "Resource: my_resource\n/path/file:1"
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure(text),
            ),
        )
        result = await make_parser().parse(xml)
        assert result.findings[0].target == "my_resource"

    async def test_classname_beats_hint(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="my.Class",
                name="Vuln",
                children_xml=junit_failure("no patterns"),
            ),
        )
        result = await make_parser(target_hint="hint.com").parse(xml)
        assert result.findings[0].target == "my.Class"

    async def test_hint_beats_unknown(self) -> None:
        xml = (
            '<testsuites><testsuite name="s">'
            '<testcase name="Vuln">'
            '<failure>no patterns at all</failure>'
            '</testcase></testsuite></testsuites>'
        )
        result = await make_parser(target_hint="my.hint").parse(xml)
        assert result.findings[0].target == "my.hint"
