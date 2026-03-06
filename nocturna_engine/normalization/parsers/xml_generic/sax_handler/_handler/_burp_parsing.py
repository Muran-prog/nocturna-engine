"""Burp Suite SAX parsing mixin — startElement / endElement dispatch for Burp XML."""

from __future__ import annotations

import xml.sax.xmlreader

from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.normalization.parsers.xml_generic._constants import (
    BURP_TEXT_ELEMENTS,
)


class BurpParsingMixin:
    """SAX event handlers for Burp Suite issue elements."""

    # ------------------------------------------------------------------
    # Burp parsing
    # ------------------------------------------------------------------

    def _burp_start(
        self, name: str, attrs: xml.sax.xmlreader.AttributesImpl,
    ) -> None:
        if name == "issue":
            self._in_burp_issue = True
            self._burp_issue = {}

        elif self._in_burp_issue and name in BURP_TEXT_ELEMENTS:
            self._burp_current_element = name

        # Burp <host> has an 'ip' attribute.
        if self._in_burp_issue and name == "host":
            ip = attrs.get("ip", "")
            if ip:
                self._burp_issue["host_ip"] = ip

    def _burp_end(self, name: str, text: str) -> None:
        if self._in_burp_issue and name in BURP_TEXT_ELEMENTS:
            self._burp_issue[name] = text
            self._burp_current_element = ""

        elif name == "issue" and self._in_burp_issue:
            self._in_burp_issue = False
            self._stats.total_records_processed += 1
            try:
                finding = self._burp_to_finding()
                if finding is not None:
                    self.findings.append(finding)
                    self._stats.findings_produced += 1
                else:
                    self._stats.records_skipped += 1
            except Exception as exc:
                self._stats.errors_encountered += 1
                self.issues.append(ParseIssue(
                    message=f"Failed to convert Burp issue: {exc}",
                    error=exc,
                ))
