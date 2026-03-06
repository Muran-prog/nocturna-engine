"""Edge-case focused tests for NormalizationOrigin attachment through the HTML parser."""

from __future__ import annotations







from tests.normalization.html.conftest import (
    html_table,
    make_parser,
    wrap_html,
)


# ---------------------------------------------------------------------------
# Origin attachment on table-extracted findings
# ---------------------------------------------------------------------------


class TestOriginAttachment:
    """Verify NormalizationOrigin metadata on table-extracted findings."""

    async def test_finding_has_normalization_key(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "high", "Cross-site scripting"]],
        )
        result = await parser.parse(wrap_html(table))
        meta = result.findings[0].metadata
        assert "_normalization" in meta

    async def test_parser_name_is_html(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "high", "Cross-site scripting"]],
        )
        result = await parser.parse(wrap_html(table))
        assert result.findings[0].metadata["_normalization"]["parser_name"] == "html"

    async def test_tool_name_matches_config(self) -> None:
        parser = make_parser(tool_name="nikto")
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Dir listing", "medium", "Directory listing found"]],
        )
        result = await parser.parse(wrap_html(table))
        assert result.findings[0].metadata["_normalization"]["tool_name"] == "nikto"

    async def test_source_format_is_html(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "low", "Some bug"]],
        )
        result = await parser.parse(wrap_html(table))
        assert result.findings[0].metadata["_normalization"]["source_format"] == "html"

    async def test_source_reference_from_config(self) -> None:
        parser = make_parser(source_reference="/tmp/report.html")
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "low", "Some bug"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        assert origin["source_reference"] == "/tmp/report.html"

    async def test_source_reference_none_by_default(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "low", "Some bug"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        assert origin["source_reference"] is None

    async def test_original_severity_preserved(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "HIGH", "Desc"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        assert origin["original_severity"] == "HIGH"

    async def test_original_severity_empty_defaults_to_info_string(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "", "Desc"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        # Empty severity cell → raw_severity falls back to "info"
        assert origin["original_severity"] == "info"

    async def test_normalized_at_timestamp_present(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "low", "Desc"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        assert "normalized_at" in origin
        assert origin["normalized_at"] is not None

    async def test_origin_on_multiple_findings(self) -> None:
        parser = make_parser(tool_name="scanner")
        table = html_table(
            ["Name", "Severity", "Description"],
            [
                ["Finding A", "high", "First"],
                ["Finding B", "low", "Second"],
            ],
        )
        result = await parser.parse(wrap_html(table))
        assert len(result.findings) == 2
        for finding in result.findings:
            assert "_normalization" in finding.metadata
            assert finding.metadata["_normalization"]["tool_name"] == "scanner"


# ---------------------------------------------------------------------------
# preserve_raw control
# ---------------------------------------------------------------------------


class TestOriginPreserveRaw:
    """Test original_record preservation controlled by config."""

    async def test_preserve_raw_true_has_cells(self) -> None:
        parser = make_parser(preserve_raw=True)
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "high", "Cross-site scripting"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        assert origin["original_record"] is not None
        assert "cells" in origin["original_record"]
        assert origin["original_record"]["cells"] == ["XSS", "high", "Cross-site scripting"]

    async def test_preserve_raw_false_no_original_record(self) -> None:
        parser = make_parser(preserve_raw=False)
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "high", "Cross-site scripting"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        assert origin["original_record"] is None

    async def test_preserve_raw_default_is_true(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "high", "Cross-site scripting"]],
        )
        result = await parser.parse(wrap_html(table))
        origin = result.findings[0].metadata["_normalization"]
        # Default preserve_raw is True
        assert origin["original_record"] is not None


# ---------------------------------------------------------------------------
# Origin on fallback CVE findings
# ---------------------------------------------------------------------------


class TestOriginFallback:
    """Verify that fallback CVE findings also get origin metadata."""

    async def test_fallback_finding_has_origin(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>Found CVE-2024-5678 in scan report.</p>")
        result = await parser.parse(html)
        assert len(result.findings) == 1
        meta = result.findings[0].metadata
        assert "_normalization" in meta

    async def test_fallback_origin_parser_name(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>CVE-2024-1111 detected.</p>")
        result = await parser.parse(html)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["parser_name"] == "html"

    async def test_fallback_origin_tool_name(self) -> None:
        parser = make_parser(tool_name="custom_tool")
        html = wrap_html("<p>CVE-2024-1111 detected.</p>")
        result = await parser.parse(html)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["tool_name"] == "custom_tool"

    async def test_fallback_origin_source_format(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>CVE-2024-1111 detected.</p>")
        result = await parser.parse(html)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["source_format"] == "html"

    async def test_fallback_origin_original_severity_is_high(self) -> None:
        parser = make_parser()
        html = wrap_html("<p>CVE-2024-1111 detected.</p>")
        result = await parser.parse(html)
        origin = result.findings[0].metadata["_normalization"]
        assert origin["original_severity"] == "high"
