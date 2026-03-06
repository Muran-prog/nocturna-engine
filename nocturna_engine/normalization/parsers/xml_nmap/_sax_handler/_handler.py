"""SAX handler that extracts host/port/service/script data from nmap XML."""

from __future__ import annotations

import xml.sax
import xml.sax.handler
from typing import Any

import structlog

from nocturna_engine.normalization.parsers.base import ParseIssue
from nocturna_engine.normalization.parsers.base.base_xml_sax import BaseNocturnaContentHandler
from nocturna_engine.normalization.parsers.xml_nmap._sax_handler._converters import (
    _FindingConverterMixin,
)

logger = structlog.get_logger("normalization.parser.xml_nmap")


class _NmapSaxHandler(BaseNocturnaContentHandler, _FindingConverterMixin):
    """SAX handler that extracts host/port/service/script data from nmap XML."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # State tracking during SAX parsing.
        self._current_host: str = ""
        self._current_host_state: str = ""
        self._current_port: dict[str, Any] = {}
        self._current_service: dict[str, Any] = {}
        self._in_host = False
        self._in_port = False
        self._current_script_id: str = ""
        self._current_script_output: str = ""
        self._scripts: list[dict[str, str]] = []

    def startElement(self, name: str, attrs: xml.sax.xmlreader.AttributesImpl) -> None:
        if name == "host":
            self._in_host = True
            self._current_host = ""
            self._current_host_state = ""
            self._scripts = []

        elif name == "status" and self._in_host:
            self._current_host_state = attrs.get("state", "")

        elif name == "address" and self._in_host:
            addr_type = attrs.get("addrtype", "")
            addr = attrs.get("addr", "")
            if addr_type in ("ipv4", "ipv6") and addr and not self._current_host:
                self._current_host = addr

        elif name == "hostname" and self._in_host:
            hostname = attrs.get("name", "")
            if hostname and not self._current_host:
                self._current_host = hostname

        elif name == "port":
            self._in_port = True
            self._current_port = {
                "protocol": attrs.get("protocol", "tcp"),
                "portid": attrs.get("portid", ""),
            }
            self._current_service = {}
            self._scripts = []

        elif name == "state" and self._in_port:
            self._current_port["state"] = attrs.get("state", "")
            self._current_port["reason"] = attrs.get("reason", "")

        elif name == "service" and self._in_port:
            self._current_service = {
                "name": attrs.get("name", ""),
                "product": attrs.get("product", ""),
                "version": attrs.get("version", ""),
                "extrainfo": attrs.get("extrainfo", ""),
                "tunnel": attrs.get("tunnel", ""),
                "method": attrs.get("method", ""),
            }

        elif name == "script":
            self._current_script_id = attrs.get("id", "")
            self._current_script_output = attrs.get("output", "")

        self._char_buffer = []

    def endElement(self, name: str) -> None:
        if name == "script" and self._current_script_id:
            self._scripts.append({
                "id": self._current_script_id,
                "output": self._current_script_output,
            })
            self._current_script_id = ""
            self._current_script_output = ""

        elif name == "port" and self._in_port:
            self._in_port = False
            self._emit_finding(
                self._port_to_finding,
                error_context=f"port {self._current_port}",
            )
            # Also create findings for vuln-related scripts.
            for script in self._scripts:
                if self._is_vuln_script(script["id"]):
                    self._emit_finding(
                        lambda s=script: self._script_to_finding(s),
                        error_context=f"script {script.get('id')}",
                    )
            self._scripts = []

        elif name == "host":
            self._in_host = False
