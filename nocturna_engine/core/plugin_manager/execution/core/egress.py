"""Subprocess egress preflight helpers for core execution."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from nocturna_engine.core.plugin_v2 import EgressPolicyEvaluator, PluginPolicy
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class PluginSubprocessEgressMixin:
    async def _validate_subprocess_egress_preflight(
        self,
        *,
        tool_name: str,
        tool: Any,
        request: ScanRequest,
        started_at: datetime,
        policy: PluginPolicy | None,
    ) -> ScanResult | None:
        binary_name = str(getattr(tool, "binary_name", "") or "").strip()
        if not binary_name:
            return None

        requires_network = bool(getattr(tool, "requires_network", False) or getattr(tool, "requires_api", False))
        if not requires_network:
            return None

        effective_policy = self._resolve_egress_policy_for_dispatch(request=request, policy=policy)
        if effective_policy is None:
            return None

        evaluator = EgressPolicyEvaluator(effective_policy)
        if not evaluator.is_configured:
            return None

        try:
            probes = await self._collect_subprocess_egress_probes(tool=tool, request=request)
        except Exception as probe_error:
            return await self._build_dispatch_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                reason_code="egress_probe_error",
                error_message=(
                    f"Egress preflight denied for tool '{tool_name}': "
                    f"egress probe hook failed ({probe_error}). Fail-closed."
                ),
                remediation="Fix the plugin's preflight_egress_targets() hook.",
                context={"tool": tool_name, "probe_error": str(probe_error)},
            )
        if not probes:
            return None

        for probe in probes:
            normalized_probe = self._normalize_egress_probe(probe=probe)
            if normalized_probe is None:
                continue

            decision = evaluator.evaluate(
                endpoint_text=normalized_probe.get("endpoint_text"),
                host=normalized_probe.get("host"),
                ip=normalized_probe.get("ip"),
                port=normalized_probe.get("port"),
                protocol=normalized_probe.get("protocol"),
                source=normalized_probe.get("source"),
            )
            if decision.allowed:
                continue

            reason = decision.reason or "policy_denied:egress"
            reason_code = decision.reason_code or "policy_denied_egress"
            diagnostics = decision.as_context()
            diagnostics.update(
                {
                    "tool": tool_name,
                    "policy_reason": reason,
                }
            )
            endpoint_label = self._format_egress_endpoint_label(diagnostics)
            policy_rule = diagnostics.get("policy_rule")
            policy_rule_text = f" (rule: {policy_rule})" if isinstance(policy_rule, str) and policy_rule else ""
            return await self._build_dispatch_failure_result(
                request=request,
                tool_name=tool_name,
                started_at=started_at,
                reason_code=reason_code,
                error_message=(
                    f"Egress preflight denied endpoint '{endpoint_label}' for tool '{tool_name}': "
                    f"{reason}{policy_rule_text}."
                ),
                remediation="Adjust policy egress rules or target/options for this tool.",
                context=diagnostics,
            )
        return None

    def _resolve_egress_policy_for_dispatch(
        self,
        *,
        request: ScanRequest,
        policy: PluginPolicy | None,
    ) -> PluginPolicy | None:
        if policy is not None:
            return policy
        policy_result = self._resolve_policy_result(
            request=request,
            for_v2_execution=self.is_feature_enabled("plugin_system_v2"),
        )
        if not policy_result.valid:
            return None
        return policy_result.policy

    async def _collect_subprocess_egress_probes(
        self,
        *,
        tool: Any,
        request: ScanRequest,
    ) -> list[Any]:
        hook = getattr(tool, "preflight_egress_targets", None)
        if not callable(hook):
            return []
        try:
            probes = hook(request)
            if hasattr(probes, "__await__"):
                probes = await probes
        except Exception as hook_error:
            raise RuntimeError(
                f"preflight_egress_targets hook failed for {type(tool).__name__}: {hook_error}"
            ) from hook_error
        if probes is None:
            return []
        if isinstance(probes, list | tuple | set):
            return list(probes)
        return [probes]

    @staticmethod
    def _normalize_egress_probe(probe: Any) -> dict[str, Any] | None:
        if isinstance(probe, str):
            candidate = probe.strip()
            if not candidate:
                return None
            return {"endpoint_text": candidate, "source": "probe"}

        if not isinstance(probe, Mapping):
            return None

        endpoint_text_value = probe.get("endpoint_text")
        if endpoint_text_value is None:
            endpoint_text_value = probe.get("endpoint")
        if endpoint_text_value is None:
            endpoint_text_value = probe.get("url")
        endpoint_text = str(endpoint_text_value).strip() if endpoint_text_value is not None else None
        if endpoint_text == "":
            endpoint_text = None

        host_value = probe.get("host")
        host = str(host_value).strip() if host_value is not None and str(host_value).strip() else None
        ip_value = probe.get("ip")
        ip = str(ip_value).strip() if ip_value is not None and str(ip_value).strip() else None
        protocol_value = probe.get("protocol")
        protocol = str(protocol_value).strip().lower() if protocol_value is not None and str(protocol_value).strip() else None

        port: int | None = None
        port_value = probe.get("port")
        if port_value is not None and str(port_value).strip():
            try:
                candidate_port = int(str(port_value).strip())
            except (TypeError, ValueError):
                candidate_port = None
            if candidate_port is not None and 1 <= candidate_port <= 65535:
                port = candidate_port

        source_value = probe.get("source")
        source = str(source_value).strip() if source_value is not None and str(source_value).strip() else "probe"

        if endpoint_text is None and host is None and ip is None:
            return None
        return {
            "endpoint_text": endpoint_text,
            "host": host,
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "source": source,
        }

    @staticmethod
    def _format_egress_endpoint_label(diagnostics: Mapping[str, Any]) -> str:
        host = diagnostics.get("host")
        ip_value = diagnostics.get("ip")
        port = diagnostics.get("port")
        protocol = diagnostics.get("protocol")

        endpoint = str(host or ip_value or "unknown")
        if isinstance(port, int):
            endpoint = f"{endpoint}:{port}"
        if isinstance(protocol, str) and protocol:
            endpoint = f"{protocol}://{endpoint}"
        return endpoint
