"""Nessus ReportItem → Finding converter mixin."""

from __future__ import annotations

from typing import Any

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.parsers.xml_generic._constants import NESSUS_SEVERITY_MAP
from nocturna_engine.normalization.parsers.xml_generic._utils import (
    build_parser_origin,
    extract_cwe,
    extract_first_cve,
    parse_cvss_score,
    safe_int,
    truncate,
)


class NessusConverterMixin:
    """Convert Nessus ReportItem data to Finding objects.

    Expects the host class to provide:
    - ``self._config`` (ParserConfig)
    - ``self._preserve_raw`` (bool)
    - ``self._current_host`` (str)
    - ``self._nessus_item_attrs`` (dict[str, str]) — ReportItem XML attributes
    - ``self._nessus_item_text`` (dict[str, str]) — child element text content
    """

    def _nessus_to_finding(self) -> Finding | None:
        """Convert accumulated Nessus ReportItem data to a Finding.

        Returns:
            Finding if the item is a real vulnerability (severity > 0),
            or None for informational-only items that should be skipped.
        """
        attrs: dict[str, str] = self._nessus_item_attrs  # type: ignore[attr-defined]
        text: dict[str, str] = self._nessus_item_text  # type: ignore[attr-defined]

        plugin_name = attrs.get("pluginName", "") or text.get("plugin_name", "")
        raw_severity_str = attrs.get("severity", "0")
        port_str = attrs.get("port", "0")
        protocol = attrs.get("protocol", "tcp")
        plugin_id = attrs.get("pluginID", "")

        raw_severity = safe_int(raw_severity_str, 0)
        severity = NESSUS_SEVERITY_MAP.get(raw_severity, SeverityLevel.INFO)

        # Skip severity-0 items only if they have no meaningful content.
        if raw_severity == 0 and not text.get("plugin_output", "").strip():
            return None

        target = self._current_host or self._config.target_hint or "unknown"  # type: ignore[attr-defined]

        title = plugin_name or f"Nessus Plugin {plugin_id}"
        title = title[:200]

        description = text.get("description", "") or text.get("synopsis", "")
        if not description:
            description = f"Nessus plugin {plugin_id} ({plugin_name}) detected on {target}."

        # CVE extraction: prefer explicit <cve> element, fallback to text scanning.
        cve_text = text.get("cve", "")
        cve = extract_first_cve(cve_text) if cve_text else None
        if not cve and description:
            cve = extract_first_cve(description)

        # CWE extraction.
        cwe_text = text.get("cwe", "")
        cwe = extract_cwe(cwe_text) if cwe_text else None
        if not cwe and description:
            cwe = extract_cwe(description)

        # CVSS extraction: prefer cvss3, fallback to cvss2.
        cvss: float | None = None
        cvss3_text = text.get("cvss3_base_score", "")
        cvss2_text = text.get("cvss_base_score", "")
        if cvss3_text:
            cvss = parse_cvss_score(cvss3_text)
        if cvss is None and cvss2_text:
            cvss = parse_cvss_score(cvss2_text)

        port = safe_int(port_str, 0)

        evidence: dict[str, Any] = {
            "plugin_id": plugin_id,
            "port": port,
            "protocol": protocol,
        }
        plugin_output = text.get("plugin_output", "")
        if plugin_output:
            evidence["plugin_output"] = truncate(plugin_output)

        solution = text.get("solution", "")
        if solution:
            evidence["solution"] = truncate(solution, 1024)

        see_also = text.get("see_also", "")
        if see_also:
            evidence["see_also"] = truncate(see_also, 1024)

        risk_factor = text.get("risk_factor", "")
        if risk_factor:
            evidence["risk_factor"] = risk_factor

        raw_record: dict[str, Any] | None = None
        if self._preserve_raw:  # type: ignore[attr-defined]
            raw_record = {
                "host": target,
                "attributes": dict(attrs),
                "elements": dict(text),
            }

        origin = build_parser_origin(
            config=self._config,  # type: ignore[attr-defined]
            original_record=raw_record,
            original_severity=raw_severity_str,
        )

        finding = Finding(
            title=title,
            description=description[:5000] if len(description) > 5000 else description,
            severity=severity,
            tool=self._config.tool_name,  # type: ignore[attr-defined]
            target=target,
            cwe=cwe,
            cvss=cvss,
            evidence=evidence,
        )
        from nocturna_engine.normalization.parsers.base.base_xml_sax import BaseNocturnaContentHandler

        return BaseNocturnaContentHandler._attach_origin_safe(finding, origin)
