"""Granular egress policy tests for plugin platform v2."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from nocturna_engine.core.event_bus import Event, EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.core.plugin_v2 import EgressPolicyEvaluator, PluginPolicy
from nocturna_engine.interfaces.base_subprocess_tool import BaseSubprocessTool
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


class SubprocessEgressProbeTool(BaseSubprocessTool):
    """Subprocess tool that exposes deterministic preflight egress probes."""

    name: ClassVar[str] = "subprocess_egress_probe"
    binary_name: ClassVar[str] = "echo"
    requires_network: ClassVar[bool] = True
    calls: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        SubprocessEgressProbeTool.calls += 1
        return ScanResult(
            request_id=request.request_id,
            tool_name=self.name,
            raw_output={"calls": SubprocessEgressProbeTool.calls},
        )

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        _ = raw_output
        _ = request
        return []

    def _build_command(self, request: ScanRequest) -> list[str]:
        _ = request
        return [self.binary_name, "ok"]

    def preflight_egress_targets(self, request: ScanRequest) -> list[dict[str, Any]]:
        options = request.options.get(self.name, {})
        if not isinstance(options, dict):
            options = {}
        return [
            {
                "host": str(options.get("host", "blocked.example.com")),
                "port": int(options.get("port", 443)),
                "protocol": str(options.get("protocol", "https")),
                "source": "options",
            }
        ]


def test_egress_host_allow_and_deny_precedence() -> None:
    policy = PluginPolicy(
        egress_allow_hosts=["example.com"],
        egress_deny_hosts=["api.example.com"],
        default_egress_action="allow",
    )
    evaluator = EgressPolicyEvaluator(policy)

    denied = evaluator.evaluate(host="api.example.com", port=443, protocol="https")
    allowed = evaluator.evaluate(host="www.example.com", port=443, protocol="https")

    assert denied.allowed is False
    assert denied.reason_code == "policy_denied_egress_host"
    assert allowed.allowed is True


def test_egress_port_and_protocol_denies() -> None:
    policy = PluginPolicy(
        egress_deny_ports=[25],
        egress_deny_protocols=["ftp"],
        default_egress_action="allow",
    )
    evaluator = EgressPolicyEvaluator(policy)

    denied_port = evaluator.evaluate(host="example.com", port=25, protocol="tcp")
    denied_protocol = evaluator.evaluate(host="example.com", port=21, protocol="ftp")

    assert denied_port.allowed is False
    assert denied_port.reason_code == "policy_denied_egress_port"
    assert denied_protocol.allowed is False
    assert denied_protocol.reason_code == "policy_denied_egress_protocol"


@pytest.mark.asyncio()
async def test_v2_subprocess_preflight_egress_denial_exposes_reason_code_and_diagnostics() -> None:
    SubprocessEgressProbeTool.calls = 0
    bus = EventBus()
    manager = PluginManager(event_bus=bus)
    manager.apply_runtime_config({"features": {"plugin_system_v2": True}})
    manager.register_tool_class(SubprocessEgressProbeTool)

    tool_errors: list[Event] = []

    async def on_tool_error(event: Event) -> None:
        tool_errors.append(event)

    bus.subscribe("on_tool_error", on_tool_error)

    request = ScanRequest(
        request_id="req-v2-egress-preflight",
        targets=[Target(domain="example.com")],
        options={
            "subprocess_egress_probe": {
                "host": "blocked.example.com",
                "port": 443,
                "protocol": "https",
            }
        },
        metadata={
            "policy": {
                "allow_subprocess": True,
                "allow_network": True,
                "allow_filesystem": True,
                "egress_deny_hosts": ["blocked.example.com"],
                "default_egress_action": "allow",
            }
        },
    )

    result = await manager.execute_tool("subprocess_egress_probe", request)

    assert result.success is False
    assert result.metadata["reason_code"] == "policy_denied_egress_host"
    context = result.metadata["error"]["context"]
    assert context["host"] == "blocked.example.com"
    assert context["port"] == 443
    assert context["protocol"] == "https"
    assert context["policy_rule"] == "blocked.example.com"
    assert SubprocessEgressProbeTool.calls == 0

    assert tool_errors
    payload = tool_errors[0].payload
    assert payload["reason_code"] == "policy_denied_egress_host"
    assert payload["context"]["host"] == "blocked.example.com"
    assert payload["context"]["port"] == 443
    assert payload["context"]["protocol"] == "https"
    assert payload["context"]["policy_rule"] == "blocked.example.com"
