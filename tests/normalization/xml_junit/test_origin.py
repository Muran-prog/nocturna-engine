"""Tests for NormalizationOrigin metadata in JUnit XML parser.

Covers: origin attachment, parser_name, tool_name, source_format,
source_reference, original_severity, preserve_raw flag.
"""

from __future__ import annotations

from tests.normalization.xml_junit.conftest import (
    junit_failure,
    make_parser,
    junit_testcase,
    wrap_junit_single_suite,
)


# ---------------------------------------------------------------------------
# Origin metadata presence
# ---------------------------------------------------------------------------


class TestOriginPresence:
    """NormalizationOrigin is attached to every finding."""

    async def test_origin_attached(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        assert "_normalization" in result.findings[0].metadata

    async def test_origin_is_dict(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert isinstance(origin, dict)


# ---------------------------------------------------------------------------
# Origin fields
# ---------------------------------------------------------------------------


class TestOriginFields:
    """Individual origin field correctness."""

    async def test_parser_name(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["parser_name"] == "xml_junit"

    async def test_tool_name_default(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["tool_name"] == "test_junit"

    async def test_tool_name_custom(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser(tool_name="trivy").parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["tool_name"] == "trivy"

    async def test_source_format(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["source_format"] == "xml_junit"

    async def test_source_reference(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser(source_reference="report.xml").parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["source_reference"] == "report.xml"

    async def test_source_reference_default_none(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["source_reference"] is None

    async def test_original_severity_captured(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="trivy.HIGH",
                name="Vuln",
                children_xml=junit_failure("text"),
            ),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["original_severity"] is not None
        assert origin["original_severity"].upper() == "HIGH"

    async def test_original_severity_none_when_no_keyword(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="com.example",
                name="Vuln",
                children_xml=junit_failure("no keyword", message="check failed"),
            ),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["original_severity"] is None

    async def test_normalized_at_present(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert "normalized_at" in origin


# ---------------------------------------------------------------------------
# preserve_raw flag
# ---------------------------------------------------------------------------


class TestPreserveRaw:
    """preserve_raw controls original_record in origin."""

    async def test_preserve_raw_true(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(
                classname="cls",
                name="Vuln",
                children_xml=junit_failure("body text", message="msg"),
            ),
        )
        result = await make_parser(preserve_raw=True).parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        raw = origin.get("original_record")
        assert raw is not None
        assert raw["testcase_name"] == "Vuln"
        assert raw["classname"] == "cls"
        assert raw["failure_message"] == "msg"
        assert "body text" in raw["failure_text"]
        assert "testsuite_name" in raw

    async def test_preserve_raw_false(self) -> None:
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser(preserve_raw=False).parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin.get("original_record") is None

    async def test_preserve_raw_default_true(self) -> None:
        """Default ParserConfig has preserve_raw=True."""
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure("text")),
        )
        result = await make_parser().parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        assert origin.get("original_record") is not None

    async def test_raw_record_text_truncated_to_4096(self) -> None:
        long_text = "A" * 8000
        xml = wrap_junit_single_suite(
            junit_testcase(name="Vuln", children_xml=junit_failure(long_text)),
        )
        result = await make_parser(preserve_raw=True).parse(xml)
        origin = result.findings[0].metadata["_normalization"]
        raw = origin["original_record"]
        assert len(raw["failure_text"]) <= 4096
