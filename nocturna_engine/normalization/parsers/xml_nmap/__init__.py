"""Nmap XML parser with SAX-based streaming for large scan results."""

from nocturna_engine.normalization.parsers.xml_nmap._sax_handler import _NmapSaxHandler
from nocturna_engine.normalization.parsers.xml_nmap._severity import (
    _HIGH_RISK_PORTS,
    _MEDIUM_RISK_PORTS,
    _port_severity,
)
from nocturna_engine.normalization.parsers.xml_nmap._utils import (
    _build_parser_origin,
    _extract_cve_from_text,
)
from nocturna_engine.normalization.parsers.xml_nmap.parser import NmapXmlParser

__all__ = [
    "NmapXmlParser",
    "_HIGH_RISK_PORTS",
    "_MEDIUM_RISK_PORTS",
    "_NmapSaxHandler",
    "_build_parser_origin",
    "_extract_cve_from_text",
    "_port_severity",
]
