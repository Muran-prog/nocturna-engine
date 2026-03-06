"""Preflight probe inference helpers for subprocess-based tools."""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any, ClassVar
from urllib.parse import urlsplit

from nocturna_engine.models.scan_request import ScanRequest


class _PreflightProbeMixin:
    _preflight_host_option_keys: ClassVar[frozenset[str]]
    _preflight_port_option_keys: ClassVar[frozenset[str]]
    _preflight_protocol_option_keys: ClassVar[frozenset[str]]
    _domain_like_pattern: ClassVar[re.Pattern[str]]

    def preflight_egress_targets(self, request: ScanRequest) -> list[dict[str, Any]]:
        """Return explicit egress probes inferred from request targets/options."""

        probes: list[dict[str, Any]] = []
        for target in request.targets:
            if target.ip is not None:
                probes.append({"ip": str(target.ip), "source": "target.ip"})
            elif target.domain is not None and "target_path" not in target.metadata:
                probes.append({"host": target.domain, "source": "target.domain"})

        tool_options = request.options.get(self.name)
        if isinstance(tool_options, dict):
            probes.extend(self._extract_preflight_probes_from_options(tool_options))

            ports = self._extract_port_hints(tool_options)
            protocols = self._extract_protocol_hints(tool_options)
            if ports or protocols:
                target_probes = [dict(item) for item in probes if str(item.get("source", "")).startswith("target.")]
                for probe in target_probes:
                    if ports and protocols:
                        for port in ports:
                            for protocol in protocols:
                                probes.append(
                                    {
                                        **probe,
                                        "port": port,
                                        "protocol": protocol,
                                        "source": "target+options",
                                    }
                                )
                    elif ports:
                        for port in ports:
                            probes.append(
                                {
                                    **probe,
                                    "port": port,
                                    "source": "target+options",
                                }
                            )
                    else:
                        for protocol in protocols:
                            probes.append(
                                {
                                    **probe,
                                    "protocol": protocol,
                                    "source": "target+options",
                                }
                            )

        return self._dedupe_preflight_probes(probes)

    def _extract_preflight_probes_from_options(self, options: dict[str, Any]) -> list[dict[str, Any]]:
        probes: list[dict[str, Any]] = []
        for raw_key, value in options.items():
            key = str(raw_key).strip().lower()
            if key in self._preflight_host_option_keys:
                for item in self._iter_option_values(value):
                    probe = self._coerce_probe_from_value(item)
                    if probe is None:
                        continue
                    probe["source"] = f"options.{key}"
                    probes.append(probe)
                continue

            if isinstance(value, dict):
                probes.extend(self._extract_preflight_probes_from_options(value))
            elif isinstance(value, list | tuple | set):
                for nested in value:
                    if isinstance(nested, dict):
                        probes.extend(self._extract_preflight_probes_from_options(nested))
        return probes

    @staticmethod
    def _iter_option_values(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list | tuple | set):
            return [item for item in value if item is not None]
        return [value]

    @classmethod
    def _coerce_probe_from_value(cls, value: Any) -> dict[str, Any] | None:
        if isinstance(value, dict):
            host = cls._normalize_host(value.get("host") or value.get("domain"))
            ip_value = cls._normalize_ip(value.get("ip"))
            port = cls._normalize_port(value.get("port"))
            protocol = cls._normalize_protocol(value.get("protocol") or value.get("scheme"))
            if host is None and ip_value is None and value.get("url") is not None:
                return cls._coerce_probe_from_value(value.get("url"))
            if host is None and ip_value is None:
                return None
            return {
                "host": host,
                "ip": ip_value,
                "port": port,
                "protocol": protocol,
            }

        text = str(value).strip()
        if not text:
            return None
        parse_target = text if "://" in text or text.startswith("//") else f"//{text}"

        try:
            parsed = urlsplit(parse_target)
        except Exception:
            parsed = None

        host = cls._normalize_host(parsed.hostname) if parsed is not None else None
        protocol = cls._normalize_protocol(parsed.scheme) if parsed is not None else None
        port: int | None = None
        if parsed is not None:
            try:
                port = cls._normalize_port(parsed.port)
            except ValueError:
                port = None

        if host is None:
            host = cls._normalize_host(text)
        ip_value = cls._normalize_ip(host) if host is not None else cls._normalize_ip(text)
        if host is not None or ip_value is not None:
            return {
                "host": host,
                "ip": ip_value,
                "port": port,
                "protocol": protocol,
            }
        return None

    @classmethod
    def _extract_port_hints(cls, options: dict[str, Any]) -> list[int]:
        ports: list[int] = []
        for raw_key, raw_value in options.items():
            key = str(raw_key).strip().lower()
            if key not in cls._preflight_port_option_keys:
                continue
            for value in cls._iter_option_values(raw_value):
                port = cls._normalize_port(value)
                if port is not None:
                    ports.append(port)
        return sorted(set(ports))

    @classmethod
    def _extract_protocol_hints(cls, options: dict[str, Any]) -> list[str]:
        protocols: list[str] = []
        for raw_key, raw_value in options.items():
            key = str(raw_key).strip().lower()
            if key not in cls._preflight_protocol_option_keys:
                continue
            for value in cls._iter_option_values(raw_value):
                protocol = cls._normalize_protocol(value)
                if protocol is not None:
                    protocols.append(protocol)
        return sorted(set(protocols))

    @classmethod
    def _normalize_host(cls, value: Any) -> str | None:
        if value is None:
            return None
        candidate = str(value).strip().lower().rstrip(".")
        if not candidate:
            return None
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        if cls._normalize_ip(candidate) is not None:
            return candidate
        if cls._domain_like_pattern.fullmatch(candidate) is not None:
            return candidate
        return None

    @staticmethod
    def _normalize_ip(value: Any) -> str | None:
        if value is None:
            return None
        candidate = str(value).strip()
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        if not candidate:
            return None
        try:
            return str(ip_address(candidate))
        except ValueError:
            return None

    @staticmethod
    def _normalize_port(value: Any) -> int | None:
        if value is None:
            return None
        try:
            port = int(str(value).strip())
        except (TypeError, ValueError):
            return None
        if port < 1 or port > 65535:
            return None
        return port

    @staticmethod
    def _normalize_protocol(value: Any) -> str | None:
        if value is None:
            return None
        candidate = str(value).strip().lower()
        return candidate or None

    @staticmethod
    def _dedupe_preflight_probes(probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str | None, str | None, int | None, str | None, str | None]] = set()
        for probe in probes:
            host = probe.get("host")
            ip_value = probe.get("ip")
            port = probe.get("port")
            protocol = probe.get("protocol")
            source = probe.get("source")
            signature = (
                str(host).lower() if isinstance(host, str) and host else None,
                str(ip_value).lower() if isinstance(ip_value, str) and ip_value else None,
                int(port) if isinstance(port, int) else None,
                str(protocol).lower() if isinstance(protocol, str) and protocol else None,
                str(source) if isinstance(source, str) and source else None,
            )
            if signature in seen:
                continue
            seen.add(signature)
            deduped.append(dict(probe))
        return deduped
