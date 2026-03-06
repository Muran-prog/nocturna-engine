"""Format detection mixin — detects XML format from the root element."""

from __future__ import annotations

import xml.sax.xmlreader

import structlog

from nocturna_engine.normalization.parsers.xml_generic._constants import (
    ROOT_ELEMENT_MAP,
)

logger = structlog.get_logger("normalization.parser.xml_generic")


class FormatDetectionMixin:
    """Detect XML scanner format from the root element name and attributes."""

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    def _detect_format(
        self, name: str, attrs: xml.sax.xmlreader.AttributesImpl,
    ) -> None:
        """Detect XML format from the root element."""
        lowered = name.lower()

        # Direct root element lookup.
        mapped = ROOT_ELEMENT_MAP.get(lowered)
        if mapped:
            self._format = mapped
            logger.debug("xml_format_detected", format=self._format, root_element=name)
            return

        # OpenVAS: <report> that is NOT nmap (nmap already excluded by xml_nmap parser).
        if lowered == "report":
            # Check for OpenVAS-specific attributes.
            format_version = attrs.get("format_id", "") or attrs.get("type", "")
            if format_version or not attrs.get("scanner", ""):
                self._format = "openvas"
                logger.debug(
                    "xml_format_detected", format="openvas", root_element=name,
                )
                return

        # Fallback to generic.
        self._format = "generic"
        logger.debug("xml_format_fallback", root_element=name)
