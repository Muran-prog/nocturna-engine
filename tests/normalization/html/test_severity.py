"""Edge-case focused tests for severity mapping through the HTML parser."""

from __future__ import annotations



import pytest

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.severity import build_severity_map

from tests.normalization.html.conftest import (
    html_table,
    make_parser,
    wrap_html,
)


# ---------------------------------------------------------------------------
# Severity mapping via HtmlParser
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    """Test that severity values in HTML tables are mapped correctly."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", SeverityLevel.CRITICAL),
            ("CRITICAL", SeverityLevel.CRITICAL),
            ("high", SeverityLevel.HIGH),
            ("HIGH", SeverityLevel.HIGH),
            ("medium", SeverityLevel.MEDIUM),
            ("MEDIUM", SeverityLevel.MEDIUM),
            ("low", SeverityLevel.LOW),
            ("LOW", SeverityLevel.LOW),
            ("info", SeverityLevel.INFO),
            ("informational", SeverityLevel.INFO),
            ("warning", SeverityLevel.MEDIUM),
            ("error", SeverityLevel.HIGH),
            ("unknown_garbage", SeverityLevel.INFO),
        ],
        ids=[
            "critical",
            "CRITICAL",
            "high",
            "HIGH",
            "medium",
            "MEDIUM",
            "low",
            "LOW",
            "info",
            "informational",
            "warning",
            "error",
            "unmapped-falls-to-info",
        ],
    )
    async def test_severity_resolution(self, raw: str, expected: SeverityLevel) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Test Finding", raw, "A test description"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].severity == expected

    async def test_missing_severity_column_defaults_info(self) -> None:
        parser = make_parser()
        # Table with name and description but no severity column
        table = html_table(
            ["Name", "Description"],
            [["XSS", "Cross-site scripting found"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.INFO

    async def test_empty_severity_cell_defaults_info(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "", "Cross-site scripting found"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.INFO

    async def test_whitespace_only_severity_defaults_info(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["XSS", "   ", "Cross-site scripting"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.INFO


class TestSeverityWithToolOverrides:
    """Test per-tool severity override via configuration."""

    async def test_tool_override_takes_precedence(self) -> None:
        smap = build_severity_map(
            overrides={"test_html": {"custom_sev": SeverityLevel.CRITICAL}},
        )
        parser = make_parser(severity_map=smap)
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "custom_sev", "Custom severity"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.CRITICAL

    async def test_default_table_used_when_no_tool_override(self) -> None:
        smap = build_severity_map(
            overrides={"other_tool": {"custom_sev": SeverityLevel.CRITICAL}},
        )
        parser = make_parser(severity_map=smap)
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "high", "Standard high"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].severity == SeverityLevel.HIGH


class TestSeverityAliasColumns:
    """Test that severity alias column headers are recognized."""

    @pytest.mark.parametrize(
        "header",
        ["severity", "risk", "priority", "level", "rating", "impact"],
        ids=["severity", "risk", "priority", "level", "rating", "impact"],
    )
    async def test_severity_alias_header(self, header: str) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", header, "Description"],
            [["Finding", "high", "Test description"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.HIGH


class TestSeverityEdgeCases:
    """Boundary conditions for severity in HTML tables."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("crit", SeverityLevel.CRITICAL),
            ("med", SeverityLevel.MEDIUM),
            ("moderate", SeverityLevel.MEDIUM),
            ("information", SeverityLevel.INFO),
            ("none", SeverityLevel.INFO),
            ("note", SeverityLevel.LOW),
            ("urgent", SeverityLevel.CRITICAL),
            ("important", SeverityLevel.HIGH),
            ("minor", SeverityLevel.LOW),
            ("trivial", SeverityLevel.INFO),
        ],
        ids=[
            "crit",
            "med",
            "moderate",
            "information",
            "none",
            "note",
            "urgent",
            "important",
            "minor",
            "trivial",
        ],
    )
    async def test_extended_severity_labels(
        self, raw: str, expected: SeverityLevel
    ) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Finding", raw, "Desc"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert len(result.findings) == 1
        assert result.findings[0].severity == expected

    async def test_mixed_case_severity_resolved(self) -> None:
        parser = make_parser()
        table = html_table(
            ["Name", "Severity", "Description"],
            [["Bug", "CrItIcAl", "Mixed case"]],
        )
        html = wrap_html(table)
        result = await parser.parse(html)
        assert result.findings[0].severity == SeverityLevel.CRITICAL
