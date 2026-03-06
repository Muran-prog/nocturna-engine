"""SAX handler with state machine that dispatches to format-specific converters."""

from __future__ import annotations

import xml.sax
import xml.sax.handler
from typing import Any

import structlog

from nocturna_engine.normalization.parsers.base.base_xml_sax import BaseNocturnaContentHandler
from nocturna_engine.normalization.parsers.xml_generic.sax_handler._converters import (
    BurpConverterMixin,
    GenericConverterMixin,
    NessusConverterMixin,
    OpenvasConverterMixin,
)
from nocturna_engine.normalization.parsers.xml_generic.sax_handler._handler._burp_parsing import (
    BurpParsingMixin,
)
from nocturna_engine.normalization.parsers.xml_generic.sax_handler._handler._detection import (
    FormatDetectionMixin,
)
from nocturna_engine.normalization.parsers.xml_generic.sax_handler._handler._generic_parsing import (
    GenericParsingMixin,
)
from nocturna_engine.normalization.parsers.xml_generic.sax_handler._handler._nessus_parsing import (
    NessusParsingMixin,
)
from nocturna_engine.normalization.parsers.xml_generic.sax_handler._handler._openvas_parsing import (
    OpenvasParsingMixin,
)

logger = structlog.get_logger("normalization.parser.xml_generic")


class _GenericXmlSaxHandler(
    BaseNocturnaContentHandler,
    NessusConverterMixin,
    OpenvasConverterMixin,
    BurpConverterMixin,
    GenericConverterMixin,
    FormatDetectionMixin,
    NessusParsingMixin,
    OpenvasParsingMixin,
    BurpParsingMixin,
    GenericParsingMixin,
):
    """SAX handler that detects XML format by root element and parses accordingly.

    State machine states:
    - ``idle``: Before root element is seen.
    - ``nessus``: Parsing Nessus XML.
    - ``openvas``: Parsing OpenVAS XML.
    - ``burp``: Parsing Burp Suite XML.
    - ``generic``: Fallback for unknown XML formats.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

        # State machine.
        self._format: str = "idle"
        self._root_seen: bool = False
        self._element_stack: list[str] = []

        # --- Nessus state ---
        self._current_host: str = ""
        self._in_report_host: bool = False
        self._in_report_item: bool = False
        self._nessus_item_attrs: dict[str, str] = {}
        self._nessus_item_text: dict[str, str] = {}
        self._nessus_current_element: str = ""

        # --- OpenVAS state ---
        self._in_openvas_result: bool = False
        self._in_openvas_nvt: bool = False
        self._openvas_result: dict[str, str] = {}
        self._openvas_nvt: dict[str, str] = {}
        self._openvas_current_element: str = ""

        # --- Burp state ---
        self._in_burp_issue: bool = False
        self._burp_issue: dict[str, str] = {}
        self._burp_current_element: str = ""

        # --- Generic fallback state ---
        self._in_generic_element: bool = False
        self._generic_element_name: str = ""
        self._generic_element_attrs: dict[str, str] = {}
        self._generic_children: dict[str, str] = {}
        self._generic_current_child: str = ""
        self._generic_depth: int = 0

    # ------------------------------------------------------------------
    # SAX callbacks
    # ------------------------------------------------------------------

    def startElement(self, name: str, attrs: xml.sax.xmlreader.AttributesImpl) -> None:
        self._element_stack.append(name)
        self._char_buffer = []

        # Root element detection (first non-xml-declaration element).
        if not self._root_seen:
            self._root_seen = True
            self._detect_format(name, attrs)
            return

        # Dispatch to format-specific handler.
        if self._format == "nessus":
            self._nessus_start(name, attrs)
        elif self._format == "openvas":
            self._openvas_start(name, attrs)
        elif self._format == "burp":
            self._burp_start(name, attrs)
        elif self._format == "generic":
            self._generic_start(name, attrs)

    # characters() inherited from BaseNocturnaContentHandler

    def endElement(self, name: str) -> None:
        text = "".join(self._char_buffer).strip()
        self._char_buffer = []

        if self._format == "nessus":
            self._nessus_end(name, text)
        elif self._format == "openvas":
            self._openvas_end(name, text)
        elif self._format == "burp":
            self._burp_end(name, text)
        elif self._format == "generic":
            self._generic_end(name, text)

        if self._element_stack:
            self._element_stack.pop()
