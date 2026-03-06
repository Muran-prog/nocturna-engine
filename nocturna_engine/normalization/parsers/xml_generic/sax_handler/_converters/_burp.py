"""Burp Suite issue → Finding converter mixin."""

from __future__ import annotations

from typing import Any

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.parsers.xml_generic._utils import (
    build_parser_origin,
    extract_cwe,
    extract_first_cve,
    truncate,
)


class BurpConverterMixin:
    """Convert Burp Suite <issue> data to Finding objects.

    Expects the host class to provide:
    - ``self._config`` (ParserConfig)
    - ``self._preserve_raw`` (bool)
    - ``self._severity_map`` (SeverityMap)
    - ``self._burp_issue`` (dict[str, str]) — child element text content
    """

    def _burp_to_finding(self) -> Finding | None:
        """Convert accumulated Burp issue data to a Finding.

        Returns:
            Finding or None if the issue should be skipped.
        """
        issue: dict[str, str] = self._burp_issue  # type: ignore[attr-defined]

        name = issue.get("name", "")
        host = issue.get("host", "")
        path = issue.get("path", "")
        raw_severity = issue.get("severity", "")
        confidence = issue.get("confidence", "")
        issue_detail = issue.get("issueDetail", "")
        remediation_detail = issue.get("remediationDetail", "")
        issue_background = issue.get("issueBackground", "")
        vuln_classifications = issue.get("vulnerabilityClassifications", "")

        # Skip "false positive" severity.
        if raw_severity.strip().lower() == "false positive":
            return None

        # Construct target from host + path.
        target_host = host or self._config.target_hint or "unknown"  # type: ignore[attr-defined]
        target = target_host
        if path:
            # Ensure no double-slash between host and path.
            if target.endswith("/") and path.startswith("/"):
                target = target + path[1:]
            elif not target.endswith("/") and not path.startswith("/"):
                target = target + "/" + path
            else:
                target = target + path

        title = name or "Burp Suite Finding"
        title = title[:200]

        # Build description from available fields.
        description_parts: list[str] = []
        if issue_detail:
            description_parts.append(issue_detail)
        elif issue_background:
            description_parts.append(issue_background)
        if remediation_detail:
            description_parts.append(f"Remediation: {remediation_detail}")

        description = " ".join(description_parts) if description_parts else (
            f"Burp Suite detected: {name} on {target}."
        )

        # Severity via SeverityMap.resolve() for Burp severity strings.
        severity = self._severity_map.resolve(  # type: ignore[attr-defined]
            raw_severity or "info",
            tool_name="burp",
        )

        # CVE/CWE from classifications or detail text.
        cve = extract_first_cve(vuln_classifications) if vuln_classifications else None
        if not cve and issue_detail:
            cve = extract_first_cve(issue_detail)

        cwe = extract_cwe(vuln_classifications) if vuln_classifications else None
        if not cwe and issue_detail:
            cwe = extract_cwe(issue_detail)

        evidence: dict[str, Any] = {}
        if host:
            evidence["host"] = host
        if path:
            evidence["path"] = path
        if confidence:
            evidence["confidence"] = confidence
        if issue_detail:
            evidence["issue_detail"] = truncate(issue_detail)
        if remediation_detail:
            evidence["remediation_detail"] = truncate(remediation_detail, 1024)

        serial = issue.get("serialNumber", "")
        if serial:
            evidence["serial_number"] = serial

        issue_type = issue.get("type", "")
        if issue_type:
            evidence["issue_type"] = issue_type

        raw_record: dict[str, Any] | None = None
        if self._preserve_raw:  # type: ignore[attr-defined]
            raw_record = {
                "target": target,
                "issue": dict(issue),
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
            target=target if target != "unknown" else (self._config.target_hint or "unknown"),  # type: ignore[attr-defined]
            cwe=cwe,
            evidence=evidence,
        )
        from nocturna_engine.normalization.parsers.base.base_xml_sax import BaseNocturnaContentHandler

        return BaseNocturnaContentHandler._attach_origin_safe(finding, origin)
