"""Edge-case focused tests for Nikto-style HTML report parsing."""

from __future__ import annotations



import pytest

from nocturna_engine.models.finding import SeverityLevel

from tests.normalization.html.conftest import (
    html_table,
    make_parser,
    nikto_table,
    wrap_html,
)


# ---------------------------------------------------------------------------
# Nikto standard columns: URI, HTTP Method, Description
#
# The column alias mapping uses:
#   title: ["title", "name", "vulnerability", "finding", "rule", "check", "issue"]
#   target: ["target", "host", "ip", "address", "url", "hostname", "asset", "endpoint"]
#
# "URI" does not match any title alias directly.
# "URI" does match "url" via partial match ("url" not in "uri" — but "uri"
# is checked against aliases; _find_column checks `alias in header`, so
# "url" in "uri" → False). "Description" matches description alias.
# "HTTP Method" matches neither.
#
# Since there's no title alias match, rows are skipped (title is required).
# ---------------------------------------------------------------------------


class TestNiktoStandardColumns:
    """Nikto's URI/HTTP Method/Description headers have no title alias match."""

    async def test_standard_nikto_no_title_all_skipped(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = nikto_table([
            ("/admin", "GET", "Admin page found"),
            ("/backup.zip", "GET", "Backup file found"),
        ])
        html = wrap_html(table)
        result = await parser.parse(html)
        # No title column → all rows skipped
        assert len(result.findings) == 0

    async def test_standard_nikto_stats_show_skipped(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = nikto_table([
            ("/admin", "GET", "Admin page found"),
        ])
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.stats.records_skipped >= 1

    async def test_standard_nikto_no_issues(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = nikto_table([
            ("/admin", "GET", "Admin page found"),
        ])
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.issues) == 0


# ---------------------------------------------------------------------------
# Nikto table with an added title-compatible column
# ---------------------------------------------------------------------------


class TestNiktoEnhancedTable:
    """Nikto table with a vulnerability/finding/issue column produces findings."""

    @pytest.mark.parametrize(
        "title_header",
        ["Vulnerability", "Finding", "Issue", "Name", "Check", "Rule"],
        ids=["vulnerability", "finding", "issue", "name", "check", "rule"],
    )
    async def test_title_alias_column_produces_findings(
        self, title_header: str
    ) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            [title_header, "URI", "HTTP Method", "Description"],
            [["Dir listing", "/admin", "GET", "Directory listing enabled"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].title == "Dir listing"

    async def test_enhanced_nikto_description_mapped(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "URI", "HTTP Method", "Description"],
            [["OSVDB-3092", "/admin/", "GET", "Admin directory is accessible"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].description == "Admin directory is accessible"

    async def test_enhanced_nikto_tool_name_from_config(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "URI", "Description"],
            [["OSVDB-3092", "/admin/", "Admin directory"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].tool == "nikto"

    async def test_enhanced_nikto_severity_defaults_info(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "URI", "Description"],
            [["OSVDB-3092", "/admin/", "Admin dir"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        # No severity column → defaults to info
        assert result.findings[0].severity == SeverityLevel.INFO

    async def test_enhanced_nikto_with_severity_column(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "Severity", "URI", "Description"],
            [["OSVDB-3092", "medium", "/admin/", "Admin dir"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].severity == SeverityLevel.MEDIUM


# ---------------------------------------------------------------------------
# Nikto description-only column behavior
# ---------------------------------------------------------------------------


class TestNiktoDescriptionAsTitle:
    """When description alias matches but title doesn't, rows are skipped."""

    async def test_description_without_title_skipped(self) -> None:
        parser = make_parser(tool_name="nikto")
        # "Description" matches description alias, but no title alias
        table = html_table(
            ["URI", "Description"],
            [["/admin", "Admin page accessible"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 0
        assert result.stats.records_skipped >= 1

    async def test_description_and_severity_without_title_skipped(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Severity", "Description"],
            [["high", "Something dangerous found"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Multiple rows and stats
# ---------------------------------------------------------------------------


class TestNiktoMultipleRows:
    """Verify stats tracking with Nikto-like tables."""

    async def test_multiple_rows_all_skipped_without_title(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = nikto_table([
            ("/admin", "GET", "Admin page"),
            ("/backup.zip", "GET", "Backup file"),
            ("/config.php", "GET", "Config file"),
        ])
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 3
        assert result.stats.records_skipped == 3

    async def test_multiple_rows_with_title_column(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Finding", "URI", "HTTP Method", "Description"],
            [
                ["OSVDB-3092", "/admin", "GET", "Admin accessible"],
                ["OSVDB-3233", "/icons/", "GET", "Default icons dir"],
                ["OSVDB-3268", "/docs/", "GET", "Documentation dir"],
            ],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 3
        assert result.stats.findings_produced == 3

    async def test_mixed_valid_and_empty_rows(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "URI", "Description"],
            [
                ["OSVDB-3092", "/admin", "Admin dir"],
                ["", "", ""],  # empty row
                ["OSVDB-3233", "/icons/", "Icons dir"],
            ],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.stats.findings_produced == 2
        assert result.stats.records_skipped >= 1


# ---------------------------------------------------------------------------
# URI column — target mapping exploration
# ---------------------------------------------------------------------------


class TestNiktoTargetMapping:
    """Test how URI and URL columns map to finding target field."""

    async def test_url_column_maps_to_target(self) -> None:
        parser = make_parser(tool_name="nikto")
        # Use 'Detail' instead of 'Description' to avoid 'ip' partial match on target alias.
        table = html_table(
            ["Name", "URL", "Severity"],
            [["Dir listing", "http://example.com/admin", "high"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].target == "http://example.com/admin"

    async def test_host_column_maps_to_target(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "Host", "Description"],
            [["Dir listing", "example.com", "Admin dir"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].target == "example.com"

    async def test_no_target_column_uses_hint(self) -> None:
        parser = make_parser(tool_name="nikto", target_hint="scan-target.io")
        # Headers without any target alias match.
        table = html_table(
            ["Name", "Severity"],
            [["Dir listing", "high"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].target == "scan-target.io"

    async def test_no_target_column_no_hint_uses_unknown(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "Severity"],
            [["Dir listing", "high"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].target == "unknown"

    async def test_empty_target_cell_uses_hint(self) -> None:
        parser = make_parser(tool_name="nikto", target_hint="fallback.com")
        table = html_table(
            ["Name", "URL", "Severity"],
            [["Dir listing", "", "high"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].target == "fallback.com"
