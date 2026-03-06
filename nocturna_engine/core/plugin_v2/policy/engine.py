"""Policy and security controls for Plugin Platform v2."""

from __future__ import annotations

from typing import Any, Mapping

from ..contracts import PluginManifest
from .constants import (
    POLICY_REASON_DENIED_FILESYSTEM,
    POLICY_REASON_DENIED_NETWORK,
    POLICY_REASON_DENIED_SUBPROCESS,
    POLICY_REASON_INVALID,
)
from .egress import EgressPolicyEvaluator
from .models import (
    EgressDecision,
    EgressEndpoint,
    PluginPolicy,
    PolicyBuildResult,
    PolicyDecision,
)
from .types import _IPAddress


class PluginPolicyEngine:
    """Evaluates plugin manifest requirements against runtime policy."""

    def __init__(self, default_policy: PluginPolicy | None = None) -> None:
        self._default_policy = default_policy or PluginPolicy()

    def build_policy(self, policy_payload: Mapping[str, Any] | None = None) -> PluginPolicy:
        """Build effective policy.

        This compatibility method keeps legacy fail-open behavior.
        """

        return self.build_policy_result(policy_payload).policy

    def build_policy_result(
        self,
        policy_payload: Mapping[str, Any] | None = None,
        *,
        fail_closed: bool = True,
    ) -> PolicyBuildResult:
        """Build effective policy with optional fail-closed validation semantics."""

        default_copy = self._default_policy.model_copy(deep=True)
        if policy_payload is None:
            return PolicyBuildResult(policy=default_copy, valid=True)
        try:
            override = PluginPolicy.model_validate(dict(policy_payload))
        except Exception as exc:
            error_text = str(exc)
            if fail_closed:
                return PolicyBuildResult(
                    policy=default_copy,
                    valid=False,
                    reason=POLICY_REASON_INVALID,
                    reason_code=POLICY_REASON_INVALID,
                    error=error_text,
                )
            # Keep legacy fail-open behavior while exposing explicit fallback reason.
            return PolicyBuildResult(
                policy=default_copy,
                valid=True,
                reason=POLICY_REASON_INVALID,
                reason_code=POLICY_REASON_INVALID,
                error=error_text,
            )
        merged = default_copy.model_dump(mode="python")
        merged.update(override.model_dump(mode="python"))
        return PolicyBuildResult(policy=PluginPolicy.model_validate(merged), valid=True)

    def evaluate(self, manifest: PluginManifest, policy: PluginPolicy) -> PolicyDecision:
        req = manifest.execution_requirements
        if req.subprocess and not policy.allow_subprocess:
            return PolicyDecision(
                allowed=False,
                reason="policy_denied:subprocess",
                reason_code=POLICY_REASON_DENIED_SUBPROCESS,
            )
        if req.network and not policy.allow_network:
            return PolicyDecision(
                allowed=False,
                reason="policy_denied:network",
                reason_code=POLICY_REASON_DENIED_NETWORK,
            )
        if req.filesystem and not policy.allow_filesystem:
            return PolicyDecision(
                allowed=False,
                reason="policy_denied:filesystem",
                reason_code=POLICY_REASON_DENIED_FILESYSTEM,
            )

        timeout = req.max_timeout_seconds
        if policy.max_timeout_seconds is not None:
            timeout = min(timeout, policy.max_timeout_seconds) if timeout is not None else policy.max_timeout_seconds

        max_output = req.max_output_bytes
        if policy.max_output_bytes is not None:
            max_output = min(max_output, policy.max_output_bytes) if max_output is not None else policy.max_output_bytes

        return PolicyDecision(
            allowed=True,
            effective_timeout_seconds=timeout,
            effective_max_output_bytes=max_output,
            effective_retries=policy.max_retries,
        )

    def evaluate_egress(
        self,
        *,
        policy: PluginPolicy,
        endpoint: EgressEndpoint | None = None,
        endpoint_text: str | None = None,
        host: str | None = None,
        ip: str | _IPAddress | None = None,
        port: int | str | None = None,
        protocol: str | None = None,
        source: str | None = None,
    ) -> EgressDecision:
        """Evaluate runtime endpoint egress constraints."""

        evaluator = EgressPolicyEvaluator(policy)
        return evaluator.evaluate(
            endpoint=endpoint,
            endpoint_text=endpoint_text,
            host=host,
            ip=ip,
            port=port,
            protocol=protocol,
            source=source,
        )

    @staticmethod
    def invalid_policy_decision() -> PolicyDecision:
        """Return explicit deny decision for invalid policy payloads."""

        return PolicyDecision(
            allowed=False,
            reason=POLICY_REASON_INVALID,
            reason_code=POLICY_REASON_INVALID,
        )

    def evaluate_manifest_payload(self, manifest_payload: Mapping[str, Any], policy: PluginPolicy) -> PolicyDecision:
        """Evaluate policy directly from machine-readable manifest payload."""

        payload = dict(manifest_payload)
        payload.pop("implementation", None)
        manifest = PluginManifest.model_validate(payload)
        return self.evaluate(manifest, policy)
