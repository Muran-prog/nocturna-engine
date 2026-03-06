"""Normalization parsers for security tool output formats.

Importing this module triggers decorator-based registration of all
built-in parsers into the global parser registry.
"""

from nocturna_engine.normalization.parsers.base import (
    BaseParser,
    ParseIssue,
    ParseResult,
    ParserConfig,
)
from nocturna_engine.normalization.parsers.csv_generic import GenericCsvParser
from nocturna_engine.normalization.parsers.html import HtmlParser
from nocturna_engine.normalization.parsers.json_generic import GenericJsonParser
from nocturna_engine.normalization.parsers.jsonl import JsonlNormalizationParser
from nocturna_engine.normalization.parsers.plaintext import PlaintextParser
from nocturna_engine.normalization.parsers.sarif import SarifParser
from nocturna_engine.normalization.parsers.xml_nmap import NmapXmlParser
from nocturna_engine.normalization.parsers.xml_generic import GenericXmlParser
from nocturna_engine.normalization.parsers.xml_junit import JunitXmlParser

__all__ = [
    "BaseParser",
    "GenericCsvParser",
    "HtmlParser",
    "GenericXmlParser",
    "GenericJsonParser",
    "JsonlNormalizationParser",
    "JunitXmlParser",
    "NmapXmlParser",
    "ParseIssue",
    "ParseResult",
    "ParserConfig",
    "PlaintextParser",
    "SarifParser",
]
