"""Generic fallback SAX parsing mixin — startElement / endElement for unknown XML formats."""

from __future__ import annotations

import xml.sax.xmlreader

from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.normalization.parsers.xml_generic._constants import (
    GENERIC_VULN_CHILD_NAMES,
    GENERIC_VULN_ELEMENT_NAMES,
)


class GenericParsingMixin:
    """SAX event handlers for generic (unknown format) vulnerability elements."""

    # ------------------------------------------------------------------
    # Generic fallback parsing
    # ------------------------------------------------------------------

    def _generic_start(
        self, name: str, attrs: xml.sax.xmlreader.AttributesImpl,
    ) -> None:
        lowered = name.lower()

        if not self._in_generic_element and lowered in GENERIC_VULN_ELEMENT_NAMES:
            self._in_generic_element = True
            self._generic_element_name = name
            self._generic_element_attrs = dict(attrs)
            self._generic_children = {}
            self._generic_depth = len(self._element_stack)

        elif self._in_generic_element and lowered in GENERIC_VULN_CHILD_NAMES:
            self._generic_current_child = lowered

    def _generic_end(self, name: str, text: str) -> None:
        lowered = name.lower()

        if self._in_generic_element and lowered in GENERIC_VULN_CHILD_NAMES:
            if text:
                self._generic_children[lowered] = text
            self._generic_current_child = ""

        elif (
            self._in_generic_element
            and name == self._generic_element_name
            and len(self._element_stack) == self._generic_depth
        ):
            self._in_generic_element = False
            self._stats.total_records_processed += 1
            try:
                finding = self._generic_to_finding()
                if finding is not None:
                    self.findings.append(finding)
                    self._stats.findings_produced += 1
                else:
                    self._stats.records_skipped += 1
            except Exception as exc:
                self._stats.errors_encountered += 1
                self.issues.append(ParseIssue(
                    message=f"Failed to convert generic element <{name}>: {exc}",
                    error=exc,
                ))
