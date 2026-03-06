"""Finding conversion mixin for the nmap SAX handler."""

from __future__ import annotations

from typing import Any

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.parsers.base.base_xml_sax import BaseNocturnaContentHandler
from nocturna_engine.normalization.parsers.xml_nmap._severity import _port_severity
from nocturna_engine.normalization.parsers.xml_nmap._utils import (
    _build_parser_origin,
    _extract_cve_from_text,
)


class _FindingConverterMixin:
    """Mixin that converts parsed port/script data into Finding objects.

    Expects the host class to provide:
    - ``self._current_host``, ``self._current_port``, ``self._current_service``
    - ``self._config``, ``self._preserve_raw``
    """

    def _port_to_finding(self) -> Finding | None:
        """Convert a port element to a Finding."""
        state = self._current_port.get("state", "")
        if state not in ("open", "open|filtered"):
            return None

        port_id_str = self._current_port.get("portid", "")
        protocol = self._current_port.get("protocol", "tcp")
        service_name = self._current_service.get("name", "")
        product = self._current_service.get("product", "")
        version = self._current_service.get("version", "")

        try:
            port_id = int(port_id_str)
        except (ValueError, TypeError):
            port_id = 0

        target = self._current_host or self._config.target_hint or "unknown"
        severity = _port_severity(port_id, state)

        title = f"Open port {port_id}/{protocol}"
        if service_name:
            title += f" ({service_name})"

        description_parts = [f"Port {port_id}/{protocol} is {state} on {target}."]
        if service_name:
            description_parts.append(f"Service: {service_name}")
        if product:
            svc_detail = product
            if version:
                svc_detail += f" {version}"
            description_parts.append(f"Product: {svc_detail}")

        evidence: dict[str, Any] = {
            "port": port_id,
            "protocol": protocol,
            "state": state,
        }
        if service_name:
            evidence["service"] = service_name
        if product:
            evidence["product"] = product
        if version:
            evidence["version"] = version

        raw_record = None
        if self._preserve_raw:
            raw_record = {
                "host": target,
                "port": dict(self._current_port),
                "service": dict(self._current_service),
            }

        origin = _build_parser_origin(
            config=self._config,
            original_record=raw_record,
        )

        finding = Finding(
            title=title[:200],
            description=" ".join(description_parts),
            severity=severity,
            tool=self._config.tool_name,
            target=target,
            evidence=evidence,
        )
        return BaseNocturnaContentHandler._attach_origin_safe(finding, origin)

    def _script_to_finding(self, script: dict[str, str]) -> Finding | None:
        """Convert an NSE vuln script to a Finding."""
        script_id = script.get("id", "")
        output = script.get("output", "").strip()
        if not output:
            return None

        target = self._current_host or self._config.target_hint or "unknown"
        port_str = self._current_port.get("portid", "")
        protocol = self._current_port.get("protocol", "tcp")

        title = f"NSE: {script_id}"
        if port_str:
            title += f" on {port_str}/{protocol}"

        # Extract CVEs from script output.
        cve = _extract_cve_from_text(output)

        evidence: dict[str, Any] = {
            "script_id": script_id,
            "output": output[:2048],
        }
        if port_str:
            evidence["port"] = port_str
            evidence["protocol"] = protocol

        finding = Finding(
            title=title[:200],
            description=f"NSE script {script_id} output on {target}: {output[:500]}",
            severity=SeverityLevel.HIGH if cve else SeverityLevel.MEDIUM,
            tool=self._config.tool_name,
            target=target,
            cwe=None,
            evidence=evidence,
        )
        return finding

    @staticmethod
    def _is_vuln_script(script_id: str) -> bool:
        """Check if an NSE script is vulnerability-related."""
        vuln_prefixes = ("vuln", "exploit", "vulners", "vulscan", "cve-", "ssl-")
        lowered = script_id.lower()
        return any(lowered.startswith(prefix) or prefix in lowered for prefix in vuln_prefixes)
