"""Utility helpers for the nmap XML parser."""

from __future__ import annotations

from typing import Any

from nocturna_engine.normalization.parsers._shared.patterns import extract_first_cve
from nocturna_engine.normalization.parsers.base import ParserConfig


def _extract_cve_from_text(text: str) -> str | None:
    """Extract the first CVE identifier from free text."""
    return extract_first_cve(text)

def _build_parser_origin(
    *,
    config: ParserConfig,
    original_record: dict[str, Any] | None,
) -> Any:
    """Build a NormalizationOrigin for nmap parser."""
    from nocturna_engine.normalization.metadata import NormalizationOrigin
    return NormalizationOrigin(
        parser_name="xml_nmap",
        tool_name=config.tool_name,
        source_format="xml_nmap",
        source_reference=config.source_reference,
        original_record=original_record if config.preserve_raw else None,
    )
