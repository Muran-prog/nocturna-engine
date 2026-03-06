"""Fallback text extraction for HTML documents without structured tables."""

from nocturna_engine.normalization.parsers.html.fallback._text_extractor import (
    extract_cve_findings,
)

__all__ = ["extract_cve_findings"]
