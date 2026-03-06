"""Generic XML parser for security tool output (Nessus, OpenVAS, Burp, etc.)."""

from nocturna_engine.normalization.parsers.xml_generic._constants import (
    BURP_TEXT_ELEMENTS,
    NESSUS_SEVERITY_MAP,
    NESSUS_TEXT_ELEMENTS,
    OPENVAS_TEXT_ELEMENTS,
)
from nocturna_engine.normalization.parsers.xml_generic._utils import (
    build_parser_origin,
    extract_cves,
    extract_first_cve,
    parse_cvss_score,
)
from nocturna_engine.normalization.parsers.xml_generic.parser import GenericXmlParser
from nocturna_engine.normalization.parsers.xml_generic.sax_handler import _GenericXmlSaxHandler

__all__ = [
    "BURP_TEXT_ELEMENTS",
    "GenericXmlParser",
    "NESSUS_SEVERITY_MAP",
    "NESSUS_TEXT_ELEMENTS",
    "OPENVAS_TEXT_ELEMENTS",
    "_GenericXmlSaxHandler",
    "build_parser_origin",
    "extract_cves",
    "extract_first_cve",
    "parse_cvss_score",
]
