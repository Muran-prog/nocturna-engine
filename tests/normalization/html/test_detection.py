"""Tests for HTML format detection heuristics and integration."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.detector import (
    InputFormat,
    detect_format,
    _classify_html,
    _looks_like_html,
)


# ---------------------------------------------------------------------------
# _looks_like_html
# ---------------------------------------------------------------------------


class TestLooksLikeHtml:
    """Heuristic edge cases for HTML detection."""

    @pytest.mark.parametrize(
        "data",
        [
            b"<!DOCTYPE html>",
            b"<!doctype html>",
            b"<html>",
            b'<html lang="en">',
            b"<HTML>",
            b"<head><title>Report</title></head>",
            b"<body><p>Hello</p></body>",
        ],
        ids=[
            "doctype_uppercase",
            "doctype_lowercase",
            "html_tag",
            "html_lang_attr",
            "html_uppercase",
            "head_tag",
            "body_tag",
        ],
    )
    def test_html_markers_detected(self, data: bytes) -> None:
        assert _looks_like_html(data) is True

    @pytest.mark.parametrize(
        "data",
        [
            b'<?xml version="1.0"?><root/>',
            b'<?XML version="1.0"?><root/>',
            b"<root><child/></root>",
            b'{"json": true}',
            b"",
            b"<nmaprun>data</nmaprun>",
        ],
        ids=[
            "xml_declaration_lower",
            "xml_declaration_upper",
            "plain_xml",
            "json",
            "empty_bytes",
            "nmap_xml",
        ],
    )
    def test_non_html_rejected(self, data: bytes) -> None:
        assert _looks_like_html(data) is False


# ---------------------------------------------------------------------------
# _classify_html
# ---------------------------------------------------------------------------


class TestClassifyHtml:
    """_classify_html always returns a fixed DetectionResult for HTML."""

    def test_returns_html_format(self) -> None:
        result = _classify_html(b"<html></html>", tool_hint=None)
        assert result.format is InputFormat.HTML

    def test_confidence_is_090(self) -> None:
        result = _classify_html(b"<html></html>", tool_hint=None)
        assert result.confidence == 0.90

    def test_method_is_html_structure_sniff(self) -> None:
        result = _classify_html(b"<html></html>", tool_hint=None)
        assert result.method == "html_structure_sniff"

    def test_tool_hint_propagated(self) -> None:
        result = _classify_html(b"<html></html>", tool_hint="nikto")
        assert result.tool_hint == "nikto"

    def test_tool_hint_none_by_default(self) -> None:
        result = _classify_html(b"<html></html>", tool_hint=None)
        assert result.tool_hint is None


# ---------------------------------------------------------------------------
# detect_format — HTML integration
# ---------------------------------------------------------------------------


class TestDetectFormatHtmlIntegration:
    """End-to-end HTML detection through detect_format."""

    def test_doctype_html(self) -> None:
        data = "<!DOCTYPE html><html><body><p>Hello</p></body></html>"
        result = detect_format(data)
        assert result.format is InputFormat.HTML

    def test_html_body_table(self) -> None:
        data = "<html><body><table><tr><td>data</td></tr></table></body></html>"
        result = detect_format(data)
        assert result.format is InputFormat.HTML

    def test_full_html_document_not_xml_generic(self) -> None:
        data = (
            "<!DOCTYPE html><html><head><title>Report</title></head>"
            "<body><table><tr><th>Vuln</th></tr></table></body></html>"
        )
        result = detect_format(data)
        assert result.format is InputFormat.HTML
        assert result.format is not InputFormat.XML_GENERIC

    def test_html_with_leading_whitespace(self) -> None:
        data = "   \n  <!DOCTYPE html><html><body></body></html>"
        result = detect_format(data)
        assert result.format is InputFormat.HTML

    def test_bytes_input_same_as_str(self) -> None:
        data_str = "<html><body><p>content</p></body></html>"
        result_str = detect_format(data_str)
        result_bytes = detect_format(data_str.encode("utf-8"))
        assert result_str.format is result_bytes.format
        assert result_str.format is InputFormat.HTML

    def test_bom_plus_html(self) -> None:
        data = b"\xef\xbb\xbf<!DOCTYPE html><html><body></body></html>"
        result = detect_format(data)
        assert result.format is InputFormat.HTML

    def test_xml_declaration_with_html_inside(self) -> None:
        data = '<?xml version="1.0"?><html><body><p>content</p></body></html>'
        result = detect_format(data)
        assert result.format is InputFormat.HTML
        # _looks_like_html runs before _classify_xml and catches <html>
        assert result.method in ("html_structure_sniff", "html_in_xml_sniff")

    def test_xml_declaration_without_html_is_xml_generic(self) -> None:
        data = '<?xml version="1.0"?><root/>'
        result = detect_format(data)
        assert result.format is InputFormat.XML_GENERIC

    def test_format_hint_html_overrides_sniffing(self) -> None:
        data = '{"key": "value"}'
        result = detect_format(data, format_hint="html")
        assert result.format is InputFormat.HTML
        assert result.confidence == 1.0
        assert result.method == "explicit_hint"
