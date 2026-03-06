"""OpenVAS SAX parsing mixin — startElement / endElement dispatch for OpenVAS XML."""

from __future__ import annotations

import xml.sax.xmlreader

from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.normalization.parsers.xml_generic._constants import (
    OPENVAS_NVT_TEXT_ELEMENTS,
    OPENVAS_TEXT_ELEMENTS,
)


class OpenvasParsingMixin:
    """SAX event handlers for OpenVAS result / nvt elements."""

    # ------------------------------------------------------------------
    # OpenVAS parsing
    # ------------------------------------------------------------------

    def _openvas_start(
        self, name: str, attrs: xml.sax.xmlreader.AttributesImpl,
    ) -> None:
        if name == "result":
            self._in_openvas_result = True
            self._openvas_result = {}
            self._openvas_nvt = {}

        elif name == "nvt" and self._in_openvas_result:
            self._in_openvas_nvt = True
            oid = attrs.get("oid", "")
            if oid:
                self._openvas_nvt["oid"] = oid

        elif self._in_openvas_nvt and name in OPENVAS_NVT_TEXT_ELEMENTS:
            self._openvas_current_element = name

        elif self._in_openvas_result and not self._in_openvas_nvt and name in OPENVAS_TEXT_ELEMENTS:
            self._openvas_current_element = name

    def _openvas_end(self, name: str, text: str) -> None:
        if self._in_openvas_nvt and name in OPENVAS_NVT_TEXT_ELEMENTS:
            # OpenVAS <cve> inside <nvt> can repeat; concatenate.
            if name == "cve" and "cve" in self._openvas_nvt:
                existing = self._openvas_nvt["cve"]
                if text and text.upper() != "NOCVE":
                    self._openvas_nvt["cve"] = f"{existing}, {text}"
            else:
                if name == "cve" and text.upper() == "NOCVE":
                    pass  # Skip placeholder.
                else:
                    self._openvas_nvt[name] = text
            self._openvas_current_element = ""

        elif name == "nvt" and self._in_openvas_nvt:
            self._in_openvas_nvt = False

        elif self._in_openvas_result and not self._in_openvas_nvt and name in OPENVAS_TEXT_ELEMENTS:
            self._openvas_result[name] = text
            self._openvas_current_element = ""

        elif name == "result" and self._in_openvas_result:
            self._in_openvas_result = False
            self._stats.total_records_processed += 1
            try:
                finding = self._openvas_to_finding()
                if finding is not None:
                    self.findings.append(finding)
                    self._stats.findings_produced += 1
                else:
                    self._stats.records_skipped += 1
            except Exception as exc:
                self._stats.errors_encountered += 1
                self.issues.append(ParseIssue(
                    message=f"Failed to convert OpenVAS result: {exc}",
                    error=exc,
                ))
