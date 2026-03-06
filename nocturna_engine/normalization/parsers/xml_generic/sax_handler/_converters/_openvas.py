"""OpenVAS result → Finding converter mixin."""

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


class OpenvasConverterMixin:
    """Convert OpenVAS <result> data to Finding objects.

    Expects the host class to provide:
    - ``self._config`` (ParserConfig)
    - ``self._preserve_raw`` (bool)
    - ``self._severity_map`` (SeverityMap)
    - ``self._openvas_result`` (dict[str, str]) — child element text
    - ``self._openvas_nvt`` (dict[str, str]) — NVT sub-element text
    """

    def _openvas_to_finding(self) -> Finding | None:
        """Convert accumulated OpenVAS result data to a Finding.

        Returns:
            Finding or None if the result should be skipped.
        """
        result: dict[str, str] = self._openvas_result  # type: ignore[attr-defined]
        nvt: dict[str, str] = self._openvas_nvt  # type: ignore[attr-defined]

        name = result.get("name", "") or nvt.get("name", "")
        host = result.get("host", "")
        port_str = result.get("port", "")
        threat = result.get("threat", "")
        description = result.get("description", "")

        # Skip "Log" and "False Positive" unless they have meaningful content.
        threat_lower = threat.strip().lower()
        if threat_lower in ("log", "false positive") and not description.strip():
            return None

        target = host or self._config.target_hint or "unknown"  # type: ignore[attr-defined]

        title = name or "OpenVAS Finding"
        title = title[:200]

        if not description:
            description = f"OpenVAS detected: {name} on {target}."

        # Severity mapping via SeverityMap.resolve() for OpenVAS threat levels.
        severity = self._severity_map.resolve(  # type: ignore[attr-defined]
            threat or "info",
            tool_name="openvas",
        )

        # CVE extraction from NVT data.
        cve_text = nvt.get("cve", "")
        cve = extract_first_cve(cve_text) if cve_text else None
        if not cve and description:
            cve = extract_first_cve(description)

        # CWE extraction from tags or description.
        tags = nvt.get("tags", "")
        cwe = extract_cwe(tags) if tags else None
        if not cwe and description:
            cwe = extract_cwe(description)

        # CVSS from NVT.
        cvss: float | None = None
        cvss_text = nvt.get("cvss_base", "")
        if cvss_text:
            cvss = parse_cvss_score(cvss_text)

        evidence: dict[str, Any] = {}
        if port_str:
            evidence["port"] = port_str
        if threat:
            evidence["threat"] = threat

        nvt_oid = nvt.get("oid", "")
        if nvt_oid:
            evidence["nvt_oid"] = nvt_oid

        solution = nvt.get("solution", "")
        if solution:
            evidence["solution"] = truncate(solution, 1024)

        if description:
            evidence["description"] = truncate(description)

        raw_record: dict[str, Any] | None = None
        if self._preserve_raw:  # type: ignore[attr-defined]
            raw_record = {
                "host": target,
                "result": dict(result),
                "nvt": dict(nvt),
            }

        origin = build_parser_origin(
            config=self._config,  # type: ignore[attr-defined]
            original_record=raw_record,
            original_severity=threat,
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
