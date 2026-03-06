"""Shared fixtures and HTML builders for HTML parser tests."""

from __future__ import annotations

from typing import Any

import pytest

from nocturna_engine.normalization.parsers.base import ParserConfig
from nocturna_engine.normalization.parsers.html import HtmlParser
from nocturna_engine.normalization.severity import build_severity_map


# ---------------------------------------------------------------------------
# Config / parser factory
# ---------------------------------------------------------------------------


def make_config(**kwargs: Any) -> ParserConfig:
    """Build a ParserConfig with sensible defaults for testing."""
    defaults: dict[str, Any] = {
        "tool_name": "test_html",
        "severity_map": build_severity_map(),
    }
    defaults.update(kwargs)
    return ParserConfig(**defaults)


def make_parser(**kwargs: Any) -> HtmlParser:
    """Build an HtmlParser with sensible defaults for testing."""
    return HtmlParser(make_config(**kwargs))


@pytest.fixture()
def parser() -> HtmlParser:
    """Default parser fixture."""
    return make_parser()


# ---------------------------------------------------------------------------
# HTML document builders
# ---------------------------------------------------------------------------


def html_table(
    headers: list[str],
    rows: list[list[str]],
    *,
    use_thead: bool = False,
) -> str:
    """Build an HTML table element."""
    header_cells = "".join(f"<th>{h}</th>" for h in headers)
    header_row = f"<tr>{header_cells}</tr>"

    data_rows = ""
    for row in rows:
        cells = "".join(f"<td>{c}</td>" for c in row)
        data_rows += f"<tr>{cells}</tr>\n"

    if use_thead:
        return (
            f"<table><thead>{header_row}</thead>"
            f"<tbody>{data_rows}</tbody></table>"
        )
    return f"<table>{header_row}\n{data_rows}</table>"


def wrap_html(body: str, *, title: str = "Test Report") -> str:
    """Wrap body content in a full HTML document."""
    return (
        f"<!DOCTYPE html><html><head><title>{title}</title></head>"
        f"<body>{body}</body></html>"
    )


def nikto_table(rows: list[tuple[str, str, str]]) -> str:
    """Build a Nikto-style HTML table.

    Each row is (URI, HTTP Method, Description).
    """
    headers = ["URI", "HTTP Method", "Description"]
    table_rows = [[uri, method, desc] for uri, method, desc in rows]
    return html_table(headers, table_rows)


def zap_table(
    rows: list[dict[str, str]],
) -> str:
    """Build a ZAP-style HTML alert table.

    Each row dict should have keys: name, risk, confidence, url, description.
    """
    headers = ["Name", "Risk", "URL", "Description", "CWE"]
    table_rows = [
        [
            r.get("name", ""),
            r.get("risk", ""),
            r.get("url", ""),
            r.get("description", ""),
            r.get("cwe", ""),
        ]
        for r in rows
    ]
    return html_table(headers, table_rows)
