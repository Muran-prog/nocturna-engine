"""SARIF v2.1.0 parser for Static Analysis Results Interchange Format."""

from nocturna_engine.normalization.parsers.sarif.constants import _SARIF_LEVEL_MAP
from nocturna_engine.normalization.parsers.sarif.extractors import (
    build_rule_index,
    build_sarif_evidence,
    extract_cwe,
    extract_cvss,
    extract_message,
    extract_target,
    extract_tool_name,
    is_suppressed,
    resolve_severity,
)
from nocturna_engine.normalization.parsers.sarif.parser import SarifParser

__all__ = [
    "SarifParser",
    "_SARIF_LEVEL_MAP",
    "build_rule_index",
    "build_sarif_evidence",
    "extract_cwe",
    "extract_cvss",
    "extract_message",
    "extract_target",
    "extract_tool_name",
    "is_suppressed",
    "resolve_severity",
]
