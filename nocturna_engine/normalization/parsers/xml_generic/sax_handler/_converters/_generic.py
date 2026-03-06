"""Generic fallback converter for unknown XML vulnerability formats."""

from __future__ import annotations

from typing import Any

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.parsers.xml_generic._utils import (
    build_parser_origin,
    extract_cwe,
    extract_first_cve,
    parse_cvss_score,
    truncate,
)


class GenericConverterMixin:
    """Convert generic vulnerability-like XML elements to Finding objects.

    Expects the host class to provide:
    - ``self._config`` (ParserConfig)
    - ``self._preserve_raw`` (bool)
    - ``self._severity_map`` (SeverityMap)
    - ``self._generic_element_name`` (str) — parent element tag name
    - ``self._generic_element_attrs`` (dict[str, str]) — XML attributes
    - ``self._generic_children`` (dict[str, str]) — child element text content
    """

    def _generic_to_finding(self) -> Finding | None:
        """Convert accumulated generic element data to a Finding.

        Returns:
            Finding or None if insufficient data is present.
        """
        children: dict[str, str] = self._generic_children  # type: ignore[attr-defined]
        attrs: dict[str, str] = self._generic_element_attrs  # type: ignore[attr-defined]
        element_name: str = self._generic_element_name  # type: ignore[attr-defined]

        # Try to extract a title from common element names.
        title = (
            children.get("title", "")
            or children.get("name", "")
            or children.get("summary", "")
            or attrs.get("name", "")
            or attrs.get("title", "")
        )
        if not title:
            title = f"XML {element_name} finding"
        title = title[:200]

        # Description from available fields.
        description = (
            children.get("description", "")
            or children.get("detail", "")
            or children.get("impact", "")
            or children.get("output", "")
        )
        if not description:
            description = f"Finding detected from XML element <{element_name}>."

        # Target from available fields.
        target = (
            children.get("host", "")
            or children.get("target", "")
            or children.get("ip", "")
            or children.get("url", "")
            or attrs.get("host", "")
            or attrs.get("target", "")
            or attrs.get("ip", "")
            or self._config.target_hint  # type: ignore[attr-defined]
            or "unknown"
        )

        # Severity resolution.
        raw_severity = (
            children.get("severity", "")
            or children.get("risk", "")
            or children.get("threat", "")
            or attrs.get("severity", "")
            or attrs.get("risk", "")
        )
        severity = self._severity_map.resolve(  # type: ignore[attr-defined]
            raw_severity or "info",
            tool_name=self._config.tool_name,  # type: ignore[attr-defined]
        )

        # CVE/CWE/CVSS extraction.
        cve_text = children.get("cve", "") or ""
        cve = extract_first_cve(cve_text) if cve_text else None
        if not cve:
            cve = extract_first_cve(description)

        cwe_text = children.get("cwe", "") or ""
        cwe = extract_cwe(cwe_text) if cwe_text else None
        if not cwe:
            cwe = extract_cwe(description)

        cvss: float | None = None
        cvss_text = children.get("cvss", "") or ""
        if cvss_text:
            cvss = parse_cvss_score(cvss_text)

        # Build evidence from all collected child elements.
        evidence: dict[str, Any] = {}
        port = children.get("port", "") or attrs.get("port", "")
        if port:
            evidence["port"] = port

        solution = children.get("solution", "") or children.get("remediation", "")
        if solution:
            evidence["solution"] = truncate(solution, 1024)

        output = children.get("output", "") or children.get("evidence", "")
        if output:
            evidence["output"] = truncate(output)

        reference = children.get("reference", "")
        if reference:
            evidence["reference"] = truncate(reference, 1024)

        evidence["source_element"] = element_name

        raw_record: dict[str, Any] | None = None
        if self._preserve_raw:  # type: ignore[attr-defined]
            raw_record = {
                "element": element_name,
                "attributes": dict(attrs),
                "children": dict(children),
            }

        origin = build_parser_origin(
            config=self._config,  # type: ignore[attr-defined]
            original_record=raw_record,
            original_severity=raw_severity,
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
