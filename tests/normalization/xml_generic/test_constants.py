"""Tests for nocturna_engine.normalization.parsers.xml_generic._constants."""

from __future__ import annotations

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers.xml_generic._constants import (
    BURP_TEXT_ELEMENTS,
    GENERIC_VULN_CHILD_NAMES,
    GENERIC_VULN_ELEMENT_NAMES,
    NESSUS_SEVERITY_MAP,
    NESSUS_TEXT_ELEMENTS,
    OPENVAS_NVT_TEXT_ELEMENTS,
    OPENVAS_TEXT_ELEMENTS,
    ROOT_ELEMENT_MAP,
)


class TestNessusSeverityMap:
    """Verify the hardcoded Nessus severity → SeverityLevel mapping."""

    def test_all_five_levels_present(self) -> None:
        assert set(NESSUS_SEVERITY_MAP.keys()) == {0, 1, 2, 3, 4}

    def test_zero_is_info(self) -> None:
        assert NESSUS_SEVERITY_MAP[0] == SeverityLevel.INFO

    def test_one_is_low(self) -> None:
        assert NESSUS_SEVERITY_MAP[1] == SeverityLevel.LOW

    def test_two_is_medium(self) -> None:
        assert NESSUS_SEVERITY_MAP[2] == SeverityLevel.MEDIUM

    def test_three_is_high(self) -> None:
        assert NESSUS_SEVERITY_MAP[3] == SeverityLevel.HIGH

    def test_four_is_critical(self) -> None:
        assert NESSUS_SEVERITY_MAP[4] == SeverityLevel.CRITICAL

    def test_values_are_all_severity_levels(self) -> None:
        for val in NESSUS_SEVERITY_MAP.values():
            assert isinstance(val, SeverityLevel)


class TestRootElementMap:
    """Verify root element → format detection mapping."""

    def test_nessus_v2_root(self) -> None:
        assert ROOT_ELEMENT_MAP["nessusclientdata_v2"] == "nessus"

    def test_nessus_v1_root(self) -> None:
        assert ROOT_ELEMENT_MAP["nessusclientdata"] == "nessus"

    def test_burp_root(self) -> None:
        assert ROOT_ELEMENT_MAP["issues"] == "burp"

    def test_all_keys_lowercase(self) -> None:
        for key in ROOT_ELEMENT_MAP:
            assert key == key.lower()


class TestElementNameSets:
    """Verify element name sets contain expected critical entries."""

    def test_nessus_has_core_elements(self) -> None:
        expected = {"description", "solution", "cve", "cwe", "cvss3_base_score", "plugin_output"}
        assert expected.issubset(NESSUS_TEXT_ELEMENTS)

    def test_openvas_has_core_elements(self) -> None:
        expected = {"name", "host", "port", "threat", "description"}
        assert expected.issubset(OPENVAS_TEXT_ELEMENTS)

    def test_openvas_nvt_has_cve(self) -> None:
        assert "cve" in OPENVAS_NVT_TEXT_ELEMENTS
        assert "cvss_base" in OPENVAS_NVT_TEXT_ELEMENTS

    def test_burp_has_core_elements(self) -> None:
        expected = {"name", "host", "path", "severity", "confidence", "issueDetail"}
        assert expected.issubset(BURP_TEXT_ELEMENTS)

    def test_generic_vuln_element_names_not_empty(self) -> None:
        assert len(GENERIC_VULN_ELEMENT_NAMES) >= 5
        assert "vulnerability" in GENERIC_VULN_ELEMENT_NAMES
        assert "finding" in GENERIC_VULN_ELEMENT_NAMES

    def test_generic_vuln_child_names_not_empty(self) -> None:
        assert len(GENERIC_VULN_CHILD_NAMES) >= 10
        assert "name" in GENERIC_VULN_CHILD_NAMES
        assert "severity" in GENERIC_VULN_CHILD_NAMES

    def test_all_sets_are_frozenset(self) -> None:
        assert isinstance(NESSUS_TEXT_ELEMENTS, frozenset)
        assert isinstance(OPENVAS_TEXT_ELEMENTS, frozenset)
        assert isinstance(OPENVAS_NVT_TEXT_ELEMENTS, frozenset)
        assert isinstance(BURP_TEXT_ELEMENTS, frozenset)
        assert isinstance(GENERIC_VULN_ELEMENT_NAMES, frozenset)
        assert isinstance(GENERIC_VULN_CHILD_NAMES, frozenset)
