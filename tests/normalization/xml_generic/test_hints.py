"""Tests for new hint aliases in _resolve_hint."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.detector._hints import _resolve_hint
from nocturna_engine.normalization.detector._types import InputFormat


class TestNewHintAliases:
    @pytest.mark.parametrize(
        "hint",
        [
            "nessus",
            "nessus_xml",
            "openvas",
            "openvas_xml",
            "burp",
            "burp_xml",
            "burpsuite",
            "qualys",
            "qualys_xml",
            "nikto",
            "nikto_xml",
            "xml_generic",
        ],
        ids=[
            "nessus",
            "nessus_xml",
            "openvas",
            "openvas_xml",
            "burp",
            "burp_xml",
            "burpsuite",
            "qualys",
            "qualys_xml",
            "nikto",
            "nikto_xml",
            "xml_generic",
        ],
    )
    def test_alias_resolves_to_xml_generic(self, hint: str) -> None:
        assert _resolve_hint(hint) == InputFormat.XML_GENERIC

    @pytest.mark.parametrize(
        "hint",
        ["Nessus", "NESSUS", "OpenVAS", "BURP", "Qualys", "NIKTO"],
    )
    def test_case_insensitive(self, hint: str) -> None:
        assert _resolve_hint(hint) == InputFormat.XML_GENERIC

    def test_nessus_with_dashes(self) -> None:
        # "nessus-xml" → normalized to "nessus_xml"
        assert _resolve_hint("nessus-xml") == InputFormat.XML_GENERIC

    def test_burp_with_spaces(self) -> None:
        # "burp xml" → normalized to "burp_xml"
        assert _resolve_hint("burp xml") == InputFormat.XML_GENERIC


class TestExistingAliasesNotBroken:
    """Ensure the existing aliases still work after our additions."""

    def test_nmap(self) -> None:
        assert _resolve_hint("nmap") == InputFormat.XML_NMAP

    def test_sarif(self) -> None:
        assert _resolve_hint("sarif") == InputFormat.SARIF

    def test_json(self) -> None:
        assert _resolve_hint("json") == InputFormat.JSON

    def test_csv(self) -> None:
        assert _resolve_hint("csv") == InputFormat.CSV

    def test_xml_generic_via_xml(self) -> None:
        assert _resolve_hint("xml") == InputFormat.XML_GENERIC

    def test_unknown_returns_none(self) -> None:
        assert _resolve_hint("totally_unknown_format") is None
