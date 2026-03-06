"""Plugin manager AI planning helpers."""

from __future__ import annotations

from typing import Any, Mapping

from nocturna_engine.core.plugin_v2 import AIPlan, POLICY_REASON_INVALID, PluginHealthStatus, parse_ai_dsl


class PluginManagerPlanningMixin:
    """Capability-aware planning operations for plugin manager."""

    def plan_capability_aware(
        self,
        *,
        target: str,
        goal: str = "full",
        mode: str = "auto",
        health_status: dict[str, Any] | None = None,
        policy_payload: Mapping[str, Any] | None = None,
        fail_closed: bool | None = None,
    ) -> AIPlan:
        """Build explainable capability-aware plan."""

        normalized_health = None
        if health_status:
            normalized_health = {}
            for name, payload in health_status.items():
                normalized_health[name] = self._health_orchestrator_status_from_payload(name, payload)
        strict_fail_closed = (
            self._is_policy_fail_closed_enabled()
            if fail_closed is None
            else bool(fail_closed)
        )
        policy_result = self._policy_engine.build_policy_result(
            policy_payload,
            fail_closed=strict_fail_closed,
        )
        if not policy_result.valid:
            skipped = {
                name: POLICY_REASON_INVALID
                for name in self.describe_all_tools(machine_readable=True).keys()
            }
            return AIPlan(
                target=target,
                goal=goal,
                mode=mode,
                steps=[],
                skipped=skipped,
            )
        return self._planner.plan(
            target=target,
            goal=goal,
            mode=mode,
            plugin_descriptions=self.describe_all_tools(machine_readable=True),
            health_status=normalized_health,
            policy=policy_result.policy,
        )

    def plan_from_dsl(self, dsl: str) -> AIPlan:
        """Build capability-aware plan from short AI DSL."""

        payload = parse_ai_dsl(dsl)
        target = payload.get("target", "")
        goal = payload.get("goal", "full")
        mode = payload.get("mode", "auto")
        return self.plan_capability_aware(
            target=target,
            goal=goal,
            mode=mode,
            policy_payload=self._extract_policy_from_dsl(payload),
        )

    @staticmethod
    def _extract_policy_from_dsl(payload: Mapping[str, str]) -> Mapping[str, Any]:
        safe_value = str(payload.get("safe", "")).lower()
        if safe_value in {"1", "true", "yes"}:
            return {
                "allow_network": False,
                "allow_subprocess": False,
                "allow_filesystem": False,
                "max_timeout_seconds": 20.0,
                "max_output_bytes": 262144,
                "max_retries": 0,
                "circuit_breaker_threshold": 1,
                "quarantine_seconds": 1800.0,
                "strict_quarantine": True,
                "allow_cache": False,
                "egress_allow_hosts": [],
                "egress_deny_hosts": [],
                "egress_allow_cidrs": [],
                "egress_deny_cidrs": [],
                "egress_allow_ports": [],
                "egress_deny_ports": [],
                "egress_allow_protocols": [],
                "egress_deny_protocols": [],
                "default_egress_action": "deny",
            }
        if safe_value in {"0", "false", "no"}:
            return {
                "allow_network": True,
                "allow_subprocess": True,
                "allow_filesystem": True,
                "max_timeout_seconds": 120.0,
                "max_output_bytes": 8388608,
                "max_retries": 2,
                "circuit_breaker_threshold": 3,
                "quarantine_seconds": 120.0,
                "strict_quarantine": False,
                "allow_cache": True,
                "egress_allow_hosts": [],
                "egress_deny_hosts": [],
                "egress_allow_cidrs": [],
                "egress_deny_cidrs": [],
                "egress_allow_ports": [],
                "egress_deny_ports": [],
                "egress_allow_protocols": [],
                "egress_deny_protocols": [],
                "default_egress_action": "allow",
            }
        return {}

    @staticmethod
    def _health_orchestrator_status_from_payload(name: str, payload: Any) -> Any:
        if isinstance(payload, dict):
            return PluginHealthStatus(
                plugin_name=name,
                healthy=bool(payload.get("healthy", False)),
                reason=payload.get("reason"),
                latency_ms=int(payload.get("latency_ms", 0) or 0),
            )
        return payload
