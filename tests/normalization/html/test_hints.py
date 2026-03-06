"""Tests for HTML hint resolution via _resolve_hint."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.detector._hints import _resolve_hint
from nocturna_engine.normalization.detector import InputFormat


# ---------------------------------------------------------------------------
# HTML hint resolution
# ---------------------------------------------------------------------------


class TestHtmlHintResolution:
    """_resolve_hint returns InputFormat.HTML for all known HTML aliases."""

    @pytest.mark.parametrize(
        "alias,expected",
        [
            ("html", InputFormat.HTML),
            ("html_report", InputFormat.HTML),
            ("nikto_html", InputFormat.HTML),
            ("zap_html", InputFormat.HTML),
            ("burp_html", InputFormat.HTML),
            ("HTML", InputFormat.HTML),
            ("Html_Report", InputFormat.HTML),
            (" html ", InputFormat.HTML),
            ("html-report", InputFormat.HTML),
        ],
        ids=[
            "html_lowercase",
            "html_report",
            "nikto_html",
            "zap_html",
            "burp_html",
            "html_uppercase",
            "html_mixed_case",
            "html_with_spaces",
            "html_dash_normalized",
        ],
    )
    def test_known_html_aliases(self, alias: str, expected: InputFormat) -> None:
        assert _resolve_hint(alias) is expected

    @pytest.mark.parametrize(
        "alias",
        [
            "htm",
            "xhtml",
        ],
        ids=[
            "htm_not_known",
            "xhtml_not_known",
        ],
    )
    def test_non_html_aliases_return_none(self, alias: str) -> None:
        assert _resolve_hint(alias) is None
