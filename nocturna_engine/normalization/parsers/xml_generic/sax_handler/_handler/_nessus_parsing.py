"""Nessus SAX parsing mixin — startElement / endElement dispatch for Nessus XML."""

from __future__ import annotations

import xml.sax.xmlreader

from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.normalization.parsers.xml_generic._constants import (
    NESSUS_TEXT_ELEMENTS,
)


class NessusParsingMixin:
    """SAX event handlers for Nessus ReportHost / ReportItem elements."""

    # ------------------------------------------------------------------
    # Nessus parsing
    # ------------------------------------------------------------------

    def _nessus_start(
        self, name: str, attrs: xml.sax.xmlreader.AttributesImpl,
    ) -> None:
        if name == "ReportHost":
            self._in_report_host = True
            self._current_host = attrs.get("name", "")

        elif name == "ReportItem" and self._in_report_host:
            self._in_report_item = True
            self._nessus_item_attrs = {
                "pluginName": attrs.get("pluginName", ""),
                "severity": attrs.get("severity", "0"),
                "port": attrs.get("port", "0"),
                "protocol": attrs.get("protocol", "tcp"),
                "pluginID": attrs.get("pluginID", ""),
                "svc_name": attrs.get("svc_name", ""),
                "pluginFamily": attrs.get("pluginFamily", ""),
            }
            self._nessus_item_text = {}

        elif self._in_report_item and name in NESSUS_TEXT_ELEMENTS:
            self._nessus_current_element = name

    def _nessus_end(self, name: str, text: str) -> None:
        if self._in_report_item and name in NESSUS_TEXT_ELEMENTS:
            # Nessus <cve> can appear multiple times; concatenate.
            if name == "cve" and "cve" in self._nessus_item_text:
                self._nessus_item_text["cve"] += f", {text}"
            else:
                self._nessus_item_text[name] = text
            self._nessus_current_element = ""

        elif name == "ReportItem" and self._in_report_item:
            self._in_report_item = False
            self._stats.total_records_processed += 1
            try:
                finding = self._nessus_to_finding()
                if finding is not None:
                    self.findings.append(finding)
                    self._stats.findings_produced += 1
                else:
                    self._stats.records_skipped += 1
            except Exception as exc:
                self._stats.errors_encountered += 1
                self.issues.append(ParseIssue(
                    message=f"Failed to convert Nessus item: {exc}",
                    error=exc,
                ))

        elif name == "ReportHost":
            self._in_report_host = False
            self._current_host = ""
