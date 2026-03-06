"""SARIF data extraction helpers.

Standalone functions for extracting findings, metadata, and evidence
from SARIF v2.1.0 result and rule objects.
"""

from nocturna_engine.normalization.parsers.sarif.extractors.evidence import (
    build_sarif_evidence,
)
from nocturna_engine.normalization.parsers.sarif.extractors.message import (
    extract_message,
)
from nocturna_engine.normalization.parsers.sarif.extractors.rule import (
    build_rule_index,
    extract_tool_name,
)
from nocturna_engine.normalization.parsers.sarif.extractors.severity import (
    extract_cwe,
    extract_cvss,
    resolve_severity,
)
from nocturna_engine.normalization.parsers.sarif.extractors.suppression import (
    is_suppressed,
)
from nocturna_engine.normalization.parsers.sarif.extractors.uri import (
    _sanitize_uri,
    extract_target,
)

__all__ = [
    "_sanitize_uri",
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
