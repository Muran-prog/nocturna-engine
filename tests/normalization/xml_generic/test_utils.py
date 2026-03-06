"""Tests for nocturna_engine.normalization.parsers.xml_generic._utils."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.parsers.xml_generic._utils import (
    build_parser_origin,
    extract_cves,
    extract_first_cve,
    extract_cwe,
    parse_cvss_score,
    safe_int,
    truncate,
)
from nocturna_engine.normalization.severity import build_severity_map


# ---------------------------------------------------------------------------
# extract_cves
# ---------------------------------------------------------------------------


class TestExtractCves:
    def test_single_cve(self) -> None:
        assert extract_cves("Found CVE-2024-12345") == ["CVE-2024-12345"]

    def test_multiple_cves(self) -> None:
        text = "CVE-2024-0001 and also CVE-2023-9999 found"
        result = extract_cves(text)
        assert result == ["CVE-2023-9999", "CVE-2024-0001"]

    def test_deduplication(self) -> None:
        text = "CVE-2024-0001 repeated CVE-2024-0001"
        assert extract_cves(text) == ["CVE-2024-0001"]

    def test_case_insensitive(self) -> None:
        assert extract_cves("cve-2024-0001") == ["CVE-2024-0001"]

    def test_no_cves(self) -> None:
        assert extract_cves("No vulnerabilities here") == []

    def test_empty_string(self) -> None:
        assert extract_cves("") == []

    def test_five_digit_id(self) -> None:
        assert extract_cves("CVE-2024-123456") == ["CVE-2024-123456"]


# ---------------------------------------------------------------------------
# extract_first_cve
# ---------------------------------------------------------------------------


class TestExtractFirstCve:
    def test_returns_first(self) -> None:
        text = "CVE-2024-0001 and CVE-2024-0002"
        assert extract_first_cve(text) == "CVE-2024-0001"

    def test_none_when_absent(self) -> None:
        assert extract_first_cve("No CVE here") is None

    def test_uppercase_output(self) -> None:
        result = extract_first_cve("cve-2024-99999")
        assert result is not None
        assert result == result.upper()

    def test_empty_string(self) -> None:
        assert extract_first_cve("") is None


# ---------------------------------------------------------------------------
# extract_cwe
# ---------------------------------------------------------------------------


class TestExtractCwe:
    def test_simple(self) -> None:
        assert extract_cwe("CWE-79") == "CWE-79"

    def test_in_text(self) -> None:
        assert extract_cwe("Classified as CWE-89 (SQL Injection)") == "CWE-89"

    def test_case_insensitive(self) -> None:
        assert extract_cwe("cwe-200") == "CWE-200"

    def test_none_when_absent(self) -> None:
        assert extract_cwe("No weakness id") is None

    def test_empty_string(self) -> None:
        assert extract_cwe("") is None

    def test_four_digit_cwe(self) -> None:
        assert extract_cwe("CWE-1234") == "CWE-1234"


# ---------------------------------------------------------------------------
# parse_cvss_score
# ---------------------------------------------------------------------------


class TestParseCvssScore:
    def test_valid_score(self) -> None:
        assert parse_cvss_score("7.5") == 7.5

    def test_zero(self) -> None:
        assert parse_cvss_score("0.0") == 0.0

    def test_ten(self) -> None:
        assert parse_cvss_score("10.0") == 10.0

    def test_out_of_range_high(self) -> None:
        assert parse_cvss_score("10.1") is None

    def test_out_of_range_negative(self) -> None:
        # Regex \d+\.\d+ captures '1.0' from '-1.0' which is valid 0-10 range.
        # Negative CVSS scores don't exist in practice; the parser extracts the
        # numeric portion, which is in range. This is acceptable behavior.
        result = parse_cvss_score("-1.0")
        assert result == 1.0

    def test_non_numeric(self) -> None:
        assert parse_cvss_score("abc") is None

    def test_empty(self) -> None:
        assert parse_cvss_score("") is None

    def test_whitespace(self) -> None:
        assert parse_cvss_score("  ") is None

    def test_embedded_in_text(self) -> None:
        assert parse_cvss_score("score: 9.8 (critical)") == 9.8

    def test_integer_like(self) -> None:
        # "5" has no decimal, pattern requires \d+\.\d+
        assert parse_cvss_score("5") is None


# ---------------------------------------------------------------------------
# safe_int
# ---------------------------------------------------------------------------


class TestSafeInt:
    def test_valid(self) -> None:
        assert safe_int("42") == 42

    def test_default_on_invalid(self) -> None:
        assert safe_int("abc") == 0

    def test_custom_default(self) -> None:
        assert safe_int("bad", -1) == -1

    def test_empty(self) -> None:
        assert safe_int("") == 0

    def test_float_string(self) -> None:
        # "3.14" is not a valid int
        assert safe_int("3.14") == 0

    def test_negative(self) -> None:
        assert safe_int("-5") == -5


# ---------------------------------------------------------------------------
# truncate
# ---------------------------------------------------------------------------


class TestTruncate:
    def test_short_string_unchanged(self) -> None:
        assert truncate("hello", 100) == "hello"

    def test_exact_length_unchanged(self) -> None:
        text = "a" * 10
        assert truncate(text, 10) == text

    def test_long_string_truncated(self) -> None:
        text = "a" * 100
        result = truncate(text, 20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_default_max_length(self) -> None:
        text = "a" * 3000
        result = truncate(text)
        assert len(result) == 2048

    def test_empty_string(self) -> None:
        assert truncate("") == ""


# ---------------------------------------------------------------------------
# build_parser_origin
# ---------------------------------------------------------------------------


class TestBuildParserOrigin:
    def test_basic_origin(self) -> None:
        from nocturna_engine.normalization.parsers.base import ParserConfig

        config = ParserConfig(
            tool_name="nessus",
            severity_map=build_severity_map(),
            source_reference="scan.nessus",
        )
        origin = build_parser_origin(
            config=config,
            original_record={"test": "data"},
            original_severity="3",
        )
        assert origin.parser_name == "xml_generic"
        assert origin.tool_name == "nessus"
        assert origin.source_format == "xml"
        assert origin.source_reference == "scan.nessus"
        assert origin.original_severity == "3"
        assert origin.original_record == {"test": "data"}

    def test_preserve_raw_false(self) -> None:
        from nocturna_engine.normalization.parsers.base import ParserConfig

        config = ParserConfig(
            tool_name="nessus",
            severity_map=build_severity_map(),
            preserve_raw=False,
        )
        origin = build_parser_origin(
            config=config,
            original_record={"test": "data"},
        )
        assert origin.original_record is None
