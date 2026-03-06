"""SAX handler for extracting failure/error test cases from JUnit XML."""

from __future__ import annotations

import xml.sax
import xml.sax.handler
from typing import Any

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.metadata import NormalizationOrigin
from nocturna_engine.normalization.parsers.base.base_xml_sax import BaseNocturnaContentHandler
from nocturna_engine.normalization.parsers.xml_junit._helpers import (
    _extract_cves,
    _extract_cwes,
    _extract_severity_token,
    _extract_target,
)


# ---------------------------------------------------------------------------
# SAX handler
# ---------------------------------------------------------------------------


class _JunitSaxHandler(BaseNocturnaContentHandler):
    """SAX handler that extracts failure/error test cases from JUnit XML."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # State tracking during SAX parsing.
        self._testsuite_name: str = ""
        self._tc_classname: str = ""
        self._tc_name: str = ""
        self._in_testcase: bool = False
        self._in_failure: bool = False
        self._failure_message: str = ""
        self._failure_type: str = ""
        self._had_failure: bool = False

    # -- SAX callbacks -------------------------------------------------------

    def startElement(self, name: str, attrs: xml.sax.xmlreader.AttributesImpl) -> None:
        if name == "testsuite":
            self._testsuite_name = attrs.get("name", "")

        elif name == "testcase":
            self._in_testcase = True
            self._tc_classname = attrs.get("classname", "")
            self._tc_name = attrs.get("name", "")
            self._had_failure = False
            self._failure_message = ""
            self._failure_type = ""
            self._char_buffer = []

        elif name in ("failure", "error") and self._in_testcase:
            self._in_failure = True
            self._failure_message = attrs.get("message", "")
            self._failure_type = attrs.get("type", name)
            self._char_buffer = []

    def characters(self, content: str) -> None:
        if self._in_failure:
            self._char_buffer.append(content)

    def endElement(self, name: str) -> None:
        if name in ("failure", "error") and self._in_failure:
            self._in_failure = False
            self._had_failure = True
            # _char_buffer now holds the failure text; emit finding below on </testcase>.

        elif name == "testcase" and self._in_testcase:
            self._in_testcase = False

            if not self._had_failure:
                self._stats.total_records_processed += 1
                self._stats.records_skipped += 1
                return

            self._emit_finding(
                self._build_finding,
                error_context=f"testcase '{self._tc_name}'",
            )

    # -- Finding construction ------------------------------------------------

    def _build_finding(self) -> Finding | None:
        """Convert collected testcase + failure data into a Finding."""
        failure_text = "".join(self._char_buffer).strip()
        tc_name = self._tc_name.strip()
        classname = self._tc_classname.strip()

        if not tc_name:
            tc_name = classname or "Unknown test case"

        # Title: testcase name, truncated to 200 chars.
        title = tc_name[:200]

        # Description: failure/error text body.
        description = failure_text if failure_text else self._failure_message
        if not description or len(description.strip()) < 3:
            description = f"Test failure: {title}"

        # Severity extraction.
        severity_token = _extract_severity_token(
            classname, self._failure_message, failure_text,
        )
        if severity_token:
            severity = self._severity_map.resolve(
                severity_token, tool_name=self._config.tool_name,
            )
        else:
            severity = SeverityLevel.MEDIUM

        # Target extraction.
        target = _extract_target(
            failure_text, classname, self._config.target_hint,
        )

        # CVE / CWE extraction from all available text.
        combined_text = f"{classname} {self._failure_message} {failure_text}"
        cves = _extract_cves(combined_text)
        cwes = _extract_cwes(combined_text)

        # Evidence dict.
        evidence: dict[str, Any] = {
            "classname": classname,
            "failure_type": self._failure_type,
            "failure_message": self._failure_message,
            "testsuite_name": self._testsuite_name,
        }
        if cves:
            evidence["cves"] = cves
        if cwes:
            evidence["cwes"] = cwes

        # Raw record for forensic traceability.
        raw_record: dict[str, Any] | None = None
        if self._preserve_raw:
            raw_record = {
                "testcase_name": tc_name,
                "classname": classname,
                "failure_type": self._failure_type,
                "failure_message": self._failure_message,
                "failure_text": failure_text[:4096],
                "testsuite_name": self._testsuite_name,
            }

        # Normalization origin.
        origin = NormalizationOrigin(
            parser_name="xml_junit",
            tool_name=self._config.tool_name,
            source_format="xml_junit",
            source_reference=self._config.source_reference,
            original_severity=severity_token,
            original_record=raw_record,
        )

        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            tool=self._config.tool_name,
            target=target,
            cwe=cwes[0] if cwes else None,
            evidence=evidence,
        )

        return self._attach_origin_safe(finding, origin)
