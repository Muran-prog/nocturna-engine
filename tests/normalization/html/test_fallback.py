"""Edge-case focused tests for HTML fallback CVE text extraction."""

from __future__ import annotations



import pytest

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers.html.fallback._text_extractor import (
    extract_cve_findings,
)

from tests.normalization.html.conftest import make_parser, wrap_html, html_table


# ---------------------------------------------------------------------------
# extract_cve_findings — unit tests
# ---------------------------------------------------------------------------


class TestExtractCveFindings:
    """Unit tests for the fallback CVE text extractor function."""

    def test_single_cve_in_text(self) -> None:
        findings = extract_cve_findings(
            ["Found vulnerability CVE-2024-1234 in libfoo"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 1
        assert findings[0].title == "CVE-2024-1234"

    def test_multiple_cves(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-1111 found. Also CVE-2024-2222 is present."],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert titles == {"CVE-2024-1111", "CVE-2024-2222"}

    def test_duplicate_cve_deduplicated(self) -> None:
        findings = extract_cve_findings(
            [
                "CVE-2024-1234 appears here",
                "CVE-2024-1234 appears again in another chunk",
            ],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 1

    def test_no_cves_returns_empty(self) -> None:
        findings = extract_cve_findings(
            ["This document has no vulnerabilities whatsoever."],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 0

    def test_cve_case_insensitive(self) -> None:
        findings = extract_cve_findings(
            ["found cve-2024-1234 in lowercase"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 1
        assert findings[0].title == "CVE-2024-1234"

    def test_cve_four_digit_id(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-1234 is the minimum digit count"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 1
        assert "2024-1234" in findings[0].title

    def test_cve_five_digit_id(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-12345 has five digits"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 1
        assert "2024-12345" in findings[0].title

    def test_cve_six_digit_id(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-123456 has six digits"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 1
        assert "2024-123456" in findings[0].title

    def test_context_extracted_in_description(self) -> None:
        findings = extract_cve_findings(
            ["Buffer overflow in libfoo. CVE-2024-9999 allows remote code execution."],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 1
        assert "CVE-2024-9999" in findings[0].description
        # Surrounding context should be included
        assert "remote code execution" in findings[0].description

    def test_finding_severity_is_high(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-5678 found"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert findings[0].severity == SeverityLevel.HIGH

    def test_finding_tool_matches_tool_name(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-5678 found"],
            tool_name="my_scanner",
            target_hint="example.com",
        )
        assert findings[0].tool == "my_scanner"

    def test_finding_target_matches_target_hint(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-5678 found"],
            tool_name="test_html",
            target_hint="target.io",
        )
        assert findings[0].target == "target.io"

    def test_evidence_has_cve_key(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-5678 found"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert "cve" in findings[0].evidence
        assert "CVE-2024-5678" in findings[0].evidence["cve"]

    def test_evidence_has_extraction_method(self) -> None:
        findings = extract_cve_findings(
            ["CVE-2024-5678 found"],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert "extraction_method" in findings[0].evidence
        assert findings[0].evidence["extraction_method"] == "html_text_fallback"

    def test_empty_text_chunks(self) -> None:
        findings = extract_cve_findings(
            [],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 0

    def test_cve_across_multiple_chunks(self) -> None:
        findings = extract_cve_findings(
            [
                "First chunk: CVE-2024-0001 detected",
                "Second chunk: CVE-2024-0002 also found",
            ],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 2

    @pytest.mark.parametrize(
        "text",
        [
            "CVE-202-1234",
            "CVE-2024-123",
            "CVE2024-1234",
            "CVE-ABCD-1234",
            "some random text",
        ],
        ids=["short-year", "short-id", "missing-dash", "alpha-year", "no-cve"],
    )
    def test_invalid_cve_patterns_ignored(self, text: str) -> None:
        findings = extract_cve_findings(
            [text],
            tool_name="test_html",
            target_hint="example.com",
        )
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Fallback via HtmlParser.parse() — integration tests
# ---------------------------------------------------------------------------


class TestFallbackViaParser:
    """Integration tests for fallback path through HtmlParser.parse()."""

    async def test_html_no_tables_with_cve_uses_fallback(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>Report found CVE-2024-5678 in target application.</p>")
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].title == "CVE-2024-5678"

    async def test_html_with_security_table_no_fallback(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "high", "Cross-site scripting"]],
        )
        html = wrap_html(table + "<p>CVE-2024-9999 mentioned in text</p>")
        result = await parser.parse(html)
        # Table extraction is used, not fallback — so CVE from text is NOT extracted
        titles = [f.title for f in result.findings]
        assert "XSS" in titles
        assert "CVE-2024-9999" not in titles

    async def test_html_no_tables_no_cves_zero_findings(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>This is a clean report with no issues.</p>")
        result = await parser.parse(html)
        assert len(result.findings) == 0

    async def test_fallback_findings_have_origin_metadata(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>Found CVE-2024-1111 during scan.</p>")
        result = await parser.parse(html)
        assert len(result.findings) >= 1
        meta = result.findings[0].metadata
        assert "_normalization" in meta
        assert meta["_normalization"]["parser_name"] == "html"
        assert meta["_normalization"]["source_format"] == "html"

    async def test_fallback_multiple_cves_in_body(self) -> None:
        parser = make_parser()
        html = wrap_html(
            "<p>CVE-2024-0001 and CVE-2024-0002 were found.</p>"
            "<div>Also CVE-2024-0003 here.</div>"
        )
        result = await parser.parse(html)
        assert len(result.findings) == 3

    async def test_fallback_stats_tracked(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>CVE-2024-1111 found. CVE-2024-2222 also.</p>")
        result = await parser.parse(html)
        assert result.stats.findings_produced == 2
        assert result.stats.total_records_processed == 2

    async def test_fallback_bytes_input(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>CVE-2024-5555 in bytes</p>")
        result = await parser.parse(html.encode("utf-8"))
        assert len(result.findings) == 1
        assert result.findings[0].title == "CVE-2024-5555"
