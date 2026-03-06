"""Generic XML parser with SAX-based streaming for security tool output."""

from __future__ import annotations

import xml.sax.handler
from typing import Any

from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseXmlSaxParser
from nocturna_engine.normalization.parsers.base.parser_config import ParserConfig
from nocturna_engine.normalization.parsers.xml_generic.sax_handler import _GenericXmlSaxHandler
from nocturna_engine.normalization.registry import register_parser
from nocturna_engine.normalization.severity import SeverityMap


@register_parser(
    name="xml_generic",
    formats=[InputFormat.XML_GENERIC],
    tool_patterns=["nessus*", "openvas*", "burp*", "qualys*", "nikto*"],
    priority=5,
)
class GenericXmlParser(BaseXmlSaxParser):
    """Parser for generic security-tool XML output using SAX-based streaming.

    Supports Nessus, OpenVAS, Burp Suite, and a generic fallback for
    unrecognised XML formats containing vulnerability-like elements.
    """

    parser_name = "xml_generic"
    source_format = "xml"

    def _create_sax_handler(
        self,
        *,
        config: ParserConfig,
        stats: NormalizationStats,
        severity_map: SeverityMap | Any,
        preserve_raw: bool,
    ) -> xml.sax.handler.ContentHandler:
        return _GenericXmlSaxHandler(
            config=config,
            stats=stats,
            severity_map=severity_map,
            preserve_raw=preserve_raw,
        )
