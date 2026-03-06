"""JUnit XML parser for security tool output (Trivy, Checkov, Bandit, Safety, Snyk, ZAP).

Parses JUnit XML ``<testcase>`` elements with ``<failure>`` or ``<error>``
children into normalized :class:`Finding` objects. Passed test cases (no
failure/error child) are silently skipped.

Uses SAX-based streaming via :mod:`defusedxml` for XXE-safe parsing.
"""

from __future__ import annotations

import xml.sax.handler
from typing import Any

import structlog

from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseXmlSaxParser
from nocturna_engine.normalization.parsers.base.parser_config import ParserConfig
from nocturna_engine.normalization.parsers.xml_junit._sax_handler import _JunitSaxHandler
from nocturna_engine.normalization.registry import register_parser
from nocturna_engine.normalization.severity import SeverityMap

logger = structlog.get_logger("normalization.parser.xml_junit")


# ---------------------------------------------------------------------------
# Parser class
# ---------------------------------------------------------------------------


@register_parser(
    name="xml_junit",
    formats=[InputFormat.XML_JUNIT],
    tool_patterns=["junit", "trivy", "checkov", "safety", "snyk", "bandit"],
    priority=5,
)
class JunitXmlParser(BaseXmlSaxParser):
    """Parser for JUnit XML output from security tools.

    Handles output from Trivy, Checkov, Bandit, Safety, Snyk, ZAP and any
    other tool that produces JUnit-compatible XML. Each ``<testcase>`` with
    a ``<failure>`` or ``<error>`` child becomes a normalized Finding.
    """

    parser_name = "xml_junit"
    source_format = "xml_junit"

    def _create_sax_handler(
        self,
        *,
        config: ParserConfig,
        stats: NormalizationStats,
        severity_map: SeverityMap | Any,
        preserve_raw: bool,
    ) -> xml.sax.handler.ContentHandler:
        return _JunitSaxHandler(
            config=config,
            stats=stats,
            severity_map=severity_map,
            preserve_raw=preserve_raw,
        )
