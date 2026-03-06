"""Nmap XML parser with SAX-based streaming for large scan results."""

from __future__ import annotations

import xml.sax.handler
from typing import Any

from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base import BaseXmlSaxParser
from nocturna_engine.normalization.parsers.base.parser_config import ParserConfig
from nocturna_engine.normalization.parsers.xml_nmap._sax_handler import _NmapSaxHandler
from nocturna_engine.normalization.registry import register_parser
from nocturna_engine.normalization.severity import SeverityMap


@register_parser(
    name="xml_nmap",
    formats=[InputFormat.XML_NMAP],
    tool_patterns=["nmap*"],
    priority=10,
)
class NmapXmlParser(BaseXmlSaxParser):
    """Parser for nmap XML output using SAX-based streaming.

    Produces findings for:
    - Open ports (with service detection)
    - NSE vulnerability script results
    """

    parser_name = "xml_nmap"
    source_format = "xml_nmap"

    def _create_sax_handler(
        self,
        *,
        config: ParserConfig,
        stats: NormalizationStats,
        severity_map: SeverityMap | Any,
        preserve_raw: bool,
    ) -> xml.sax.handler.ContentHandler:
        return _NmapSaxHandler(
            config=config,
            stats=stats,
            severity_map=severity_map,
            preserve_raw=preserve_raw,
        )
