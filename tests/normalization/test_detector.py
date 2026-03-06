"""Edge-case tests for nocturna_engine.normalization.detector."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nocturna_engine.normalization.detector import (
    DetectionResult,
    InputFormat,
    _looks_like_csv,
    _looks_like_json_array,
    _looks_like_jsonl,
    _classify_json_object,
    _classify_xml,
    _resolve_hint,
    _strip_bom,
    _SNIFF_SIZE,
    detect_format,
)
from nocturna_engine.normalization.errors import FormatDetectionError


# ---------------------------------------------------------------------------
# InputFormat enum
# ---------------------------------------------------------------------------


class TestInputFormat:
    """InputFormat enum completeness and string subclass behaviour."""

    def test_all_members_present(self) -> None:
        assert set(InputFormat) == {
            InputFormat.SARIF,
            InputFormat.JSON,
            InputFormat.JSONL,
            InputFormat.XML_NMAP,
            InputFormat.XML_GENERIC,
            InputFormat.CSV,
            InputFormat.PLAINTEXT,
            InputFormat.HTML,
            InputFormat.XML_JUNIT,
        }

    def test_member_count(self) -> None:
        assert len(InputFormat) == 9

    @pytest.mark.parametrize(
        "member,value",
        [
            (InputFormat.SARIF, "sarif"),
            (InputFormat.JSON, "json"),
            (InputFormat.JSONL, "jsonl"),
            (InputFormat.XML_NMAP, "xml_nmap"),
            (InputFormat.XML_GENERIC, "xml_generic"),
            (InputFormat.XML_JUNIT, "xml_junit"),
            (InputFormat.CSV, "csv"),
            (InputFormat.PLAINTEXT, "plaintext"),
            (InputFormat.HTML, "html"),
        ],
    )
    def test_string_values(self, member: InputFormat, value: str) -> None:
        assert member.value == value

    def test_is_str_subclass(self) -> None:
        assert isinstance(InputFormat.SARIF, str)

    def test_construct_from_value(self) -> None:
        assert InputFormat("sarif") is InputFormat.SARIF

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            InputFormat("nonexistent_format")


# ---------------------------------------------------------------------------
# DetectionResult model
# ---------------------------------------------------------------------------


class TestDetectionResult:
    """DetectionResult pydantic model edge cases."""

    def test_valid_construction(self) -> None:
        r = DetectionResult(format=InputFormat.JSON, confidence=0.8, method="test")
        assert r.format is InputFormat.JSON
        assert r.confidence == 0.8
        assert r.method == "test"
        assert r.tool_hint is None

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            DetectionResult(
                format=InputFormat.JSON,
                confidence=0.5,
                method="x",
                bogus_field="nope",
            )

    @pytest.mark.parametrize("confidence", [0.0, 1.0])
    def test_confidence_boundary_valid(self, confidence: float) -> None:
        r = DetectionResult(format=InputFormat.JSON, confidence=confidence, method="b")
        assert r.confidence == confidence

    @pytest.mark.parametrize("confidence", [-0.01, 1.01, -1.0, 2.0, 100.0])
    def test_confidence_out_of_range(self, confidence: float) -> None:
        with pytest.raises(ValidationError):
            DetectionResult(format=InputFormat.JSON, confidence=confidence, method="b")

    def test_method_min_length_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            DetectionResult(format=InputFormat.JSON, confidence=0.5, method="")

    def test_tool_hint_none_by_default(self) -> None:
        r = DetectionResult(format=InputFormat.JSON, confidence=0.5, method="a")
        assert r.tool_hint is None

    def test_tool_hint_accepted(self) -> None:
        r = DetectionResult(
            format=InputFormat.JSON, confidence=0.5, method="a", tool_hint="nmap"
        )
        assert r.tool_hint == "nmap"


# ---------------------------------------------------------------------------
# _strip_bom
# ---------------------------------------------------------------------------


class TestStripBom:
    """UTF-8 BOM stripping edge cases."""

    def test_strips_utf8_bom(self) -> None:
        data = b"\xef\xbb\xbf{\"key\": 1}"
        assert _strip_bom(data) == b'{"key": 1}'

    def test_no_bom_passthrough(self) -> None:
        data = b'{"key": 1}'
        assert _strip_bom(data) is data  # identity, not copy

    def test_empty_bytes(self) -> None:
        assert _strip_bom(b"") == b""

    def test_only_bom(self) -> None:
        assert _strip_bom(b"\xef\xbb\xbf") == b""

    def test_partial_bom_not_stripped(self) -> None:
        # Only first 2 bytes of BOM — should NOT be stripped.
        assert _strip_bom(b"\xef\xbb{") == b"\xef\xbb{"


# ---------------------------------------------------------------------------
# _resolve_hint
# ---------------------------------------------------------------------------


class TestResolveHint:
    """format_hint alias resolution edge cases."""

    @pytest.mark.parametrize(
        "alias,expected",
        [
            ("sarif", InputFormat.SARIF),
            ("SARIF", InputFormat.SARIF),
            ("  sarif  ", InputFormat.SARIF),
            ("sarif2", InputFormat.SARIF),
            ("sarif_v2", InputFormat.SARIF),
            ("sarif-v2", InputFormat.SARIF),  # dash normalized to underscore
            ("json", InputFormat.JSON),
            ("JSON", InputFormat.JSON),
            ("jsonl", InputFormat.JSONL),
            ("ndjson", InputFormat.JSONL),
            ("jsonlines", InputFormat.JSONL),
            ("xml", InputFormat.XML_GENERIC),
            ("xml_nmap", InputFormat.XML_NMAP),
            ("nmap", InputFormat.XML_NMAP),
            ("nmap_xml", InputFormat.XML_NMAP),
            ("nmap-xml", InputFormat.XML_NMAP),
            ("csv", InputFormat.CSV),
            ("tsv", InputFormat.CSV),
            ("plaintext", InputFormat.PLAINTEXT),
            ("text", InputFormat.PLAINTEXT),
            ("txt", InputFormat.PLAINTEXT),
        ],
    )
    def test_known_aliases(self, alias: str, expected: InputFormat) -> None:
        assert _resolve_hint(alias) is expected

    @pytest.mark.parametrize("hint", ["unknown", "yaml", "binary", ""])
    def test_unknown_hint_returns_none(self, hint: str) -> None:
        assert _resolve_hint(hint) is None


# ---------------------------------------------------------------------------
# _looks_like_json_array
# ---------------------------------------------------------------------------


class TestLooksLikeJsonArray:
    """Heuristic edge cases for JSON array detection."""

    @pytest.mark.parametrize(
        "data",
        [
            b'[{"a": 1}]',
            b'[ {"a": 1}]',
            b'["string"]',
            b"[true, false]",
            b"[false]",
            b"[null]",
            b"[123]",
            b"[[1,2]]",
        ],
    )
    def test_looks_like_json_array(self, data: bytes) -> None:
        assert _looks_like_json_array(data) is True

    @pytest.mark.parametrize(
        "data",
        [
            b"[CRITICAL] something happened",  # uppercase tag
            b"[WARNING] alert",
            b"[ERROR] failure",
            b"[",  # just opening bracket, no inner content
        ],
    )
    def test_not_json_array(self, data: bytes) -> None:
        assert _looks_like_json_array(data) is False


# ---------------------------------------------------------------------------
# _looks_like_csv
# ---------------------------------------------------------------------------


class TestLooksLikeCsv:
    """CSV heuristic edge cases."""

    def test_comma_separated_header(self) -> None:
        assert _looks_like_csv(b"col1,col2,col3\nval1,val2,val3") is True

    def test_tab_separated_header(self) -> None:
        assert _looks_like_csv(b"col1\tcol2\tcol3\nval1\tval2\tval3") is True

    def test_single_field_not_csv(self) -> None:
        assert _looks_like_csv(b"justoneword") is False

    def test_one_comma_not_enough(self) -> None:
        # needs >= 2 commas or >= 2 tabs
        assert _looks_like_csv(b"a,b\nval1,val2") is False

    def test_json_start_rejected(self) -> None:
        assert _looks_like_csv(b'{"a":1,"b":2,"c":3}') is False

    def test_xml_start_rejected(self) -> None:
        assert _looks_like_csv(b"<root>,stuff,here") is False

    def test_array_start_rejected(self) -> None:
        assert _looks_like_csv(b"[1],2,3,4") is False

    def test_empty_first_line(self) -> None:
        assert _looks_like_csv(b"\ncol,col2,col3") is False

    def test_no_newline(self) -> None:
        # Even without newline, first line = entire data
        assert _looks_like_csv(b"a,b,c") is True


# ---------------------------------------------------------------------------
# _looks_like_jsonl
# ---------------------------------------------------------------------------


class TestLooksLikeJsonl:
    """JSONL multiline heuristic edge cases."""

    def test_two_json_lines(self) -> None:
        assert _looks_like_jsonl(b'{"a":1}\n{"b":2}') is True

    def test_single_json_line_not_enough(self) -> None:
        assert _looks_like_jsonl(b'{"a":1}') is False

    def test_empty_lines_between(self) -> None:
        # Empty lines are skipped
        assert _looks_like_jsonl(b'{"a":1}\n\n{"b":2}') is True

    def test_non_json_lines_ignored(self) -> None:
        assert _looks_like_jsonl(b"hello\nworld\nfoo") is False

    def test_mixed_json_and_text(self) -> None:
        # Only 1 json-like line among text
        assert _looks_like_jsonl(b"text line\n{\"a\":1}\nmore text") is False

    def test_five_json_lines(self) -> None:
        data = b"\n".join(b'{"n":%d}' % i for i in range(5))
        assert _looks_like_jsonl(data) is True

    def test_only_checks_first_five_lines(self) -> None:
        # Lines beyond 5 should not matter; first 5 have 0 json lines
        lines = [b"text"] * 5 + [b'{"a":1}'] * 10
        assert _looks_like_jsonl(b"\n".join(lines)) is False


# ---------------------------------------------------------------------------
# _classify_json_object
# ---------------------------------------------------------------------------


class TestClassifyJsonObject:
    """SARIF vs generic JSON classification edge cases."""

    def test_sarif_with_schema_keyword(self) -> None:
        data = b'{"$schema": "https://raw.githubusercontent.com/sarif/2.1.0", "runs": []}'
        result = _classify_json_object(data, tool_hint=None)
        assert result.format is InputFormat.SARIF
        assert result.confidence == 0.95

    def test_sarif_with_version_and_runs(self) -> None:
        data = b'{"version": "2.1.0", "runs": [{"tool": {}}]}'
        result = _classify_json_object(data, tool_hint=None)
        assert result.format is InputFormat.SARIF
        assert result.confidence == 0.8

    def test_generic_json_object(self) -> None:
        data = b'{"findings": [{"title": "xss"}]}'
        result = _classify_json_object(data, tool_hint=None)
        assert result.format is InputFormat.JSON
        assert result.confidence == 0.8

    def test_sarif_case_insensitive(self) -> None:
        data = b'{"$SCHEMA": "https://SARIF.example.com", "RUNS": []}'
        result = _classify_json_object(data, tool_hint=None)
        assert result.format is InputFormat.SARIF

    def test_tool_hint_propagated(self) -> None:
        data = b'{"findings": []}'
        result = _classify_json_object(data, tool_hint="semgrep")
        assert result.tool_hint == "semgrep"

    def test_sarif_in_content_without_schema_key(self) -> None:
        # "sarif" appears in content + "runs" key → SARIF detection
        data = b'{"description": "sarif output", "runs": [{}]}'
        result = _classify_json_object(data, tool_hint=None)
        assert result.format is InputFormat.SARIF


# ---------------------------------------------------------------------------
# _classify_xml
# ---------------------------------------------------------------------------


class TestClassifyXml:
    """Nmap vs generic XML classification edge cases."""

    def test_nmaprun_element(self) -> None:
        data = b"<?xml version='1.0'?><nmaprun>...</nmaprun>"
        result = _classify_xml(data, tool_hint=None)
        assert result.format is InputFormat.XML_NMAP
        assert result.tool_hint == "nmap"

    def test_nmap_dtd_reference(self) -> None:
        data = b'<?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "nmap.dtd"><nmaprun/>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format is InputFormat.XML_NMAP

    def test_scanner_nmap_attribute(self) -> None:
        data = b'<root scanner="nmap" />'
        result = _classify_xml(data, tool_hint=None)
        assert result.format is InputFormat.XML_NMAP
        assert result.confidence == 0.95

    def test_generic_xml(self) -> None:
        data = b'<?xml version="1.0"?><root><child/></root>'
        result = _classify_xml(data, tool_hint=None)
        assert result.format is InputFormat.XML_GENERIC
        assert result.confidence == 0.7

    def test_xml_with_nmap_tool_hint(self) -> None:
        data = b"<?xml version='1.0'?><generic/>"
        result = _classify_xml(data, tool_hint="nmap")
        assert result.format is InputFormat.XML_NMAP
        assert result.confidence == 0.85
        assert result.tool_hint == "nmap"

    def test_xml_with_unrelated_tool_hint(self) -> None:
        data = b'<?xml version="1.0"?><root/>'
        result = _classify_xml(data, tool_hint="burp")
        assert result.format is InputFormat.XML_GENERIC
        assert result.tool_hint == "burp"

    def test_nmap_detection_case_insensitive(self) -> None:
        data = b"<?xml version='1.0'?><NMAPRUN>data</NMAPRUN>"
        result = _classify_xml(data, tool_hint=None)
        assert result.format is InputFormat.XML_NMAP


# ---------------------------------------------------------------------------
# detect_format — format_hint layer
# ---------------------------------------------------------------------------


class TestDetectFormatHint:
    """Tests for explicit format_hint overriding sniffing."""

    @pytest.mark.parametrize(
        "hint,expected_format",
        [
            ("sarif", InputFormat.SARIF),
            ("SARIF", InputFormat.SARIF),
            ("sarif2", InputFormat.SARIF),
            ("sarif_v2", InputFormat.SARIF),
            ("json", InputFormat.JSON),
            ("jsonl", InputFormat.JSONL),
            ("ndjson", InputFormat.JSONL),
            ("jsonlines", InputFormat.JSONL),
            ("xml", InputFormat.XML_GENERIC),
            ("xml_nmap", InputFormat.XML_NMAP),
            ("nmap", InputFormat.XML_NMAP),
            ("nmap_xml", InputFormat.XML_NMAP),
            ("csv", InputFormat.CSV),
            ("tsv", InputFormat.CSV),
            ("plaintext", InputFormat.PLAINTEXT),
            ("text", InputFormat.PLAINTEXT),
            ("txt", InputFormat.PLAINTEXT),
        ],
    )
    def test_hint_overrides_sniffing(
        self, hint: str, expected_format: InputFormat
    ) -> None:
        # Data looks like JSON, but hint says otherwise.
        data = '{"key": "value"}'
        result = detect_format(data, format_hint=hint)
        assert result.format is expected_format
        assert result.confidence == 1.0
        assert result.method == "explicit_hint"

    def test_hint_propagates_tool_hint(self) -> None:
        result = detect_format(
            '{"key": "value"}', format_hint="json", tool_hint="custom_tool"
        )
        assert result.tool_hint == "custom_tool"

    def test_unknown_hint_falls_through_to_sniffing(self) -> None:
        result = detect_format('{"key": "value"}', format_hint="unknown_format_xyz")
        # Should fall through to JSON sniffing
        assert result.format is InputFormat.JSON
        assert result.method != "explicit_hint"


# ---------------------------------------------------------------------------
# detect_format — sniffing layer
# ---------------------------------------------------------------------------


class TestDetectFormatSniffing:
    """Structural sniffing edge cases."""

    def test_sarif_full_document(self) -> None:
        data = '{"$schema": "https://sarif.example/2.1.0", "version": "2.1.0", "runs": []}'
        result = detect_format(data)
        assert result.format is InputFormat.SARIF
        assert result.confidence >= 0.9

    def test_json_object(self) -> None:
        data = '{"some": "data", "number": 42}'
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_json_array(self) -> None:
        data = '[{"item": 1}, {"item": 2}]'
        result = detect_format(data)
        assert result.format is InputFormat.JSON
        assert "array" in result.method

    def test_jsonl_multiline(self) -> None:
        data = '{"a":1}\n{"b":2}\n{"c":3}'
        result = detect_format(data)
        assert result.format is InputFormat.JSONL

    def test_xml_nmap(self) -> None:
        data = '<?xml version="1.0"?><nmaprun scanner="nmap"><host/></nmaprun>'
        result = detect_format(data)
        assert result.format is InputFormat.XML_NMAP

    def test_xml_generic(self) -> None:
        data = '<?xml version="1.0"?><root><child/></root>'
        result = detect_format(data)
        assert result.format is InputFormat.XML_GENERIC

    def test_xml_uppercase_declaration(self) -> None:
        data = '<?XML version="1.0"?><root/>'
        result = detect_format(data)
        assert result.format is InputFormat.XML_GENERIC

    def test_xml_without_declaration(self) -> None:
        data = "<root><child attr='val'/></root>"
        result = detect_format(data)
        assert result.format is InputFormat.XML_GENERIC

    def test_csv_detection(self) -> None:
        data = "title,severity,target\nxss,high,example.com"
        result = detect_format(data)
        assert result.format is InputFormat.CSV

    def test_tsv_detection(self) -> None:
        data = "title\tseverity\ttarget\nxss\thigh\texample.com"
        result = detect_format(data)
        assert result.format is InputFormat.CSV

    def test_plaintext_fallback(self) -> None:
        data = "Just some random plaintext log output with no structure."
        result = detect_format(data)
        assert result.format is InputFormat.PLAINTEXT
        assert result.confidence == 0.3
        assert result.method == "fallback"


# ---------------------------------------------------------------------------
# detect_format — error cases
# ---------------------------------------------------------------------------


class TestDetectFormatErrors:
    """FormatDetectionError edge cases."""

    def test_empty_string_raises(self) -> None:
        with pytest.raises(FormatDetectionError, match="empty"):
            detect_format("")

    def test_empty_bytes_raises(self) -> None:
        with pytest.raises(FormatDetectionError, match="empty"):
            detect_format(b"")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(FormatDetectionError, match="empty"):
            detect_format("   \t\n  ")

    def test_whitespace_bytes_raises(self) -> None:
        with pytest.raises(FormatDetectionError, match="empty"):
            detect_format(b"   \n\t  ")

    def test_bom_only_raises(self) -> None:
        with pytest.raises(FormatDetectionError):
            detect_format(b"\xef\xbb\xbf")

    def test_bom_plus_whitespace_raises(self) -> None:
        with pytest.raises(FormatDetectionError):
            detect_format(b"\xef\xbb\xbf   \n  ")


# ---------------------------------------------------------------------------
# detect_format — bytes vs str
# ---------------------------------------------------------------------------


class TestDetectFormatInputTypes:
    """Both bytes and str inputs should work identically."""

    @pytest.mark.parametrize(
        "data_str",
        [
            '{"key": "value"}',
            '{"$schema": "sarif", "runs": []}',
            '<?xml version="1.0"?><root/>',
            "col1,col2,col3\na,b,c",
            '{"a":1}\n{"b":2}',
        ],
    )
    def test_bytes_and_str_give_same_format(self, data_str: str) -> None:
        result_str = detect_format(data_str)
        result_bytes = detect_format(data_str.encode("utf-8"))
        assert result_str.format is result_bytes.format


# ---------------------------------------------------------------------------
# detect_format — BOM handling
# ---------------------------------------------------------------------------


class TestDetectFormatBom:
    """BOM prefix should be transparently stripped."""

    def test_bom_json(self) -> None:
        data = b"\xef\xbb\xbf" + b'{"key": "value"}'
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_bom_sarif(self) -> None:
        data = b"\xef\xbb\xbf" + b'{"$schema": "sarif", "runs": []}'
        result = detect_format(data)
        assert result.format is InputFormat.SARIF

    def test_bom_xml(self) -> None:
        data = b"\xef\xbb\xbf" + b'<?xml version="1.0"?><root/>'
        result = detect_format(data)
        assert result.format is InputFormat.XML_GENERIC


# ---------------------------------------------------------------------------
# detect_format — edge-case inputs
# ---------------------------------------------------------------------------


class TestDetectFormatEdgeCases:
    """Mixed signals, large inputs, and binary garbage."""

    def test_binary_garbage_falls_to_plaintext(self) -> None:
        data = bytes(range(128, 256)) * 10
        result = detect_format(data)
        assert result.format is InputFormat.PLAINTEXT

    def test_huge_input_only_sniffs_first_bytes(self) -> None:
        # JSON object at the start, followed by huge garbage.
        header = b'{"key": "value"}'
        padding = b"x" * (_SNIFF_SIZE * 3)
        data = header + padding
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_json_with_xml_content_in_strings(self) -> None:
        data = '{"report": "<xml>content</xml>", "count": 1}'
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_critical_tag_not_json_array(self) -> None:
        data = "[CRITICAL] Something went wrong\n[ERROR] Another issue"
        result = detect_format(data)
        assert result.format is not InputFormat.JSON

    def test_leading_whitespace_before_json(self) -> None:
        data = "   \n  {\"key\": \"value\"}"
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_leading_whitespace_before_xml(self) -> None:
        data = "  \n  <?xml version='1.0'?><root/>"
        result = detect_format(data)
        assert result.format is InputFormat.XML_GENERIC

    def test_tool_hint_propagated_to_result(self) -> None:
        data = '{"key": "value"}'
        result = detect_format(data, tool_hint="my_scanner")
        assert result.tool_hint == "my_scanner"

    def test_tool_hint_with_nmap_xml(self) -> None:
        data = '<?xml version="1.0"?><root/>'
        result = detect_format(data, tool_hint="nmap")
        assert result.format is InputFormat.XML_NMAP
        assert result.tool_hint == "nmap"

    def test_jsonl_takes_priority_over_single_json_object(self) -> None:
        # Multiple JSON objects on separate lines → JSONL, not JSON
        data = '{"a":1}\n{"b":2}\n{"c":3}'
        result = detect_format(data)
        assert result.format is InputFormat.JSONL

    def test_single_json_object_not_jsonl(self) -> None:
        data = '{"a": 1}'
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_sniff_size_boundary(self) -> None:
        # Data exactly at _SNIFF_SIZE limit
        data = b'{"k":"' + b"v" * (_SNIFF_SIZE - 8) + b'"}'
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_json_array_with_numbers(self) -> None:
        data = "[1, 2, 3, 4]"
        result = detect_format(data)
        assert result.format is InputFormat.JSON

    def test_csv_not_detected_when_first_line_starts_with_brace(self) -> None:
        # First line starts with { — CSV detection should bail
        data = "{header,col2,col3\nval1,val2,val3"
        result = detect_format(data)
        assert result.format is not InputFormat.CSV

    def test_jsonl_non_brace_start_fallback(self) -> None:
        # JSONL fallback path: lines starting with [ that parse as JSON
        # Actually, jsonl checks for { only, so [ lines don't count
        data = '[1]\n[2]\n[3]'
        result = detect_format(data)
        # These start with [ but _looks_like_jsonl checks for { prefix
        assert result.format is InputFormat.JSON  # json array sniff
