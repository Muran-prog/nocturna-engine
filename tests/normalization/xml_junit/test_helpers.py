"""Unit tests for JUnit XML parser helper functions.

Tests: _extract_severity_token, _extract_target, _extract_cves, _extract_cwes.
"""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.parsers.xml_junit import (
    _extract_cves,
    _extract_cwes,
    _extract_severity_token,
    _extract_target,
)


# ---------------------------------------------------------------------------
# _extract_severity_token
# ---------------------------------------------------------------------------


class TestExtractSeverityToken:
    """Severity keyword extraction from classname, message, and text."""

    @pytest.mark.parametrize(
        "classname,expected",
        [
            ("trivy.CRITICAL", "CRITICAL"),
            ("trivy.HIGH", "HIGH"),
            ("scanner.MEDIUM", "MEDIUM"),
            ("tool.LOW", "LOW"),
            ("audit.INFO", "INFO"),
            ("audit.INFORMATIONAL", "INFORMATIONAL"),
        ],
        ids=["critical", "high", "medium", "low", "info", "informational"],
    )
    def test_severity_from_classname(self, classname: str, expected: str) -> None:
        result = _extract_severity_token(classname, "", "")
        assert result is not None
        assert result.upper() == expected.upper()

    @pytest.mark.parametrize(
        "message,expected",
        [
            ("HIGH vulnerability found", "HIGH"),
            ("CRITICAL: buffer overflow", "CRITICAL"),
            ("low risk issue", "low"),
        ],
        ids=["high-msg", "critical-msg", "low-msg"],
    )
    def test_severity_from_message(self, message: str, expected: str) -> None:
        result = _extract_severity_token("no.match", message, "")
        assert result is not None
        assert result.upper() == expected.upper()

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Severity: HIGH\nPackage: lib", "HIGH"),
            ("This is a CRITICAL issue in production", "CRITICAL"),
            ("risk level: medium or above", "medium"),
        ],
        ids=["high-text", "critical-text", "medium-text"],
    )
    def test_severity_from_text_body(self, text: str, expected: str) -> None:
        result = _extract_severity_token("no.match", "no match", text)
        assert result is not None
        assert result.upper() == expected.upper()

    def test_classname_takes_priority_over_message(self) -> None:
        result = _extract_severity_token("trivy.CRITICAL", "LOW issue", "MEDIUM text")
        assert result is not None
        assert result.upper() == "CRITICAL"

    def test_message_takes_priority_over_text(self) -> None:
        result = _extract_severity_token("no.match", "HIGH alert", "CRITICAL text")
        assert result is not None
        assert result.upper() == "HIGH"

    def test_returns_none_when_no_match(self) -> None:
        assert _extract_severity_token("com.example", "check failed", "some text") is None

    def test_empty_strings(self) -> None:
        assert _extract_severity_token("", "", "") is None

    def test_case_insensitive(self) -> None:
        result = _extract_severity_token("scanner.high", "", "")
        assert result is not None
        assert result.upper() == "HIGH"

    def test_partial_word_not_matched(self) -> None:
        """'HIGHEST' should not match HIGH due to word boundary."""
        assert _extract_severity_token("some.HIGHEST", "", "") is None

    def test_severity_embedded_in_sentence(self) -> None:
        result = _extract_severity_token("", "This is a HIGH severity vuln", "")
        assert result is not None
        assert result.upper() == "HIGH"


# ---------------------------------------------------------------------------
# _extract_target
# ---------------------------------------------------------------------------


class TestExtractTarget:
    """Target extraction from failure text with fallback chain."""

    def test_url_extracted(self) -> None:
        text = "Affected URL: https://example.com/api/v1"
        assert _extract_target(text, "cls", None) == "https://example.com/api/v1"

    def test_http_url(self) -> None:
        text = "See http://internal.corp/vuln for details"
        assert _extract_target(text, "cls", None) == "http://internal.corp/vuln"

    def test_url_takes_priority_over_resource(self) -> None:
        text = "https://example.com\nResource: aws_s3.bucket"
        assert _extract_target(text, "cls", None) == "https://example.com"

    def test_resource_line_extracted(self) -> None:
        text = "Resource: aws_s3_bucket.data\nFile: /main.tf:15"
        assert _extract_target(text, "cls", None) == "aws_s3_bucket.data"

    def test_resource_case_insensitive(self) -> None:
        text = "resource: my_resource.name"
        assert _extract_target(text, "cls", None) == "my_resource.name"

    def test_file_path_extracted(self) -> None:
        text = "Issue found in /src/main.py:42"
        assert _extract_target(text, "cls", None) == "/src/main.py:42"

    def test_file_path_without_line_number(self) -> None:
        text = "Affected file: /etc/config.yaml"
        assert _extract_target(text, "cls", None) == "/etc/config.yaml"

    def test_classname_fallback(self) -> None:
        assert _extract_target("no pattern here", "com.example.Test", None) == "com.example.Test"

    def test_target_hint_fallback(self) -> None:
        assert _extract_target("no pattern here", "", "fallback.host") == "fallback.host"

    def test_unknown_fallback(self) -> None:
        assert _extract_target("no pattern here", "", None) == "unknown"

    def test_empty_text_uses_classname(self) -> None:
        assert _extract_target("", "my.Class", None) == "my.Class"

    def test_empty_everything_returns_unknown(self) -> None:
        assert _extract_target("", "", None) == "unknown"

    def test_url_with_query_params(self) -> None:
        text = "https://example.com/api?key=val&foo=bar"
        assert _extract_target(text, "cls", None) == "https://example.com/api?key=val&foo=bar"

    def test_resource_with_whitespace(self) -> None:
        text = "Resource:    aws_iam_role.admin   "
        assert _extract_target(text, "cls", None) == "aws_iam_role.admin"


# ---------------------------------------------------------------------------
# _extract_cves
# ---------------------------------------------------------------------------


class TestExtractCves:
    """CVE identifier extraction from text."""

    def test_single_cve(self) -> None:
        assert _extract_cves("Found CVE-2024-1234") == ["CVE-2024-1234"]

    def test_multiple_cves(self) -> None:
        text = "CVE-2024-0001 and CVE-2023-99999"
        result = _extract_cves(text)
        assert result == ["CVE-2023-99999", "CVE-2024-0001"]

    def test_duplicate_cves_deduplicated(self) -> None:
        text = "CVE-2024-0001 again CVE-2024-0001"
        assert _extract_cves(text) == ["CVE-2024-0001"]

    def test_case_insensitive(self) -> None:
        assert _extract_cves("cve-2024-5678") == ["CVE-2024-5678"]

    def test_five_digit_id(self) -> None:
        assert _extract_cves("CVE-2024-12345") == ["CVE-2024-12345"]

    def test_six_digit_id(self) -> None:
        assert _extract_cves("CVE-2024-123456") == ["CVE-2024-123456"]

    def test_no_cve(self) -> None:
        assert _extract_cves("No vulnerabilities found") == []

    def test_empty_string(self) -> None:
        assert _extract_cves("") == []

    def test_cve_at_start_of_text(self) -> None:
        assert _extract_cves("CVE-2024-0001: buffer overflow") == ["CVE-2024-0001"]

    def test_cve_at_end_of_text(self) -> None:
        assert _extract_cves("Vulnerable to CVE-2024-0001") == ["CVE-2024-0001"]

    def test_results_sorted(self) -> None:
        text = "CVE-2024-9999 CVE-2024-0001 CVE-2023-1234"
        result = _extract_cves(text)
        assert result == sorted(result)

    def test_cve_too_short_id_not_matched(self) -> None:
        """CVE IDs must have at least 4 digits after the year."""
        assert _extract_cves("CVE-2024-123") == []


# ---------------------------------------------------------------------------
# _extract_cwes
# ---------------------------------------------------------------------------


class TestExtractCwes:
    """CWE identifier extraction from text."""

    def test_single_cwe(self) -> None:
        assert _extract_cwes("CWE-79 detected") == ["CWE-79"]

    def test_multiple_cwes(self) -> None:
        text = "CWE-79 and CWE-89"
        result = _extract_cwes(text)
        assert result == ["CWE-79", "CWE-89"]

    def test_duplicate_cwes_deduplicated(self) -> None:
        text = "CWE-79 again CWE-79"
        assert _extract_cwes(text) == ["CWE-79"]

    def test_case_insensitive(self) -> None:
        assert _extract_cwes("cwe-79") == ["CWE-79"]

    def test_cwe_with_large_number(self) -> None:
        assert _extract_cwes("CWE-1234") == ["CWE-1234"]

    def test_no_cwe(self) -> None:
        assert _extract_cwes("Nothing here") == []

    def test_empty_string(self) -> None:
        assert _extract_cwes("") == []

    def test_results_sorted(self) -> None:
        text = "CWE-89 CWE-22 CWE-79"
        result = _extract_cwes(text)
        assert result == sorted(result)

    def test_cwe_mixed_with_cve(self) -> None:
        """CWE extraction should not confuse with CVE."""
        text = "CVE-2024-1234 CWE-79"
        assert _extract_cwes(text) == ["CWE-79"]
