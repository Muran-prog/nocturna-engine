"""HTML parser for security tool reports (Nikto, ZAP, Burp, generic tables)."""

from nocturna_engine.normalization.parsers.html._table_extractor import (
    _ExtractedTable,
    _HtmlTableHandler,
)
from nocturna_engine.normalization.parsers.html.fallback import extract_cve_findings
from nocturna_engine.normalization.parsers.html.parser import HtmlParser

__all__ = [
    "HtmlParser",
    "_ExtractedTable",
    "_HtmlTableHandler",
    "extract_cve_findings",
]
