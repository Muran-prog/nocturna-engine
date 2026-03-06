"""Policy helpers for plugin execution."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.core.plugin_v2 import PluginPolicy, PolicyBuildResult
from nocturna_engine.models.scan_request import ScanRequest


class PluginExecutionPolicyMixin:
    """Policy resolution helper for execution flows."""

    @staticmethod
    def _is_ai_fail_closed_request(request: ScanRequest) -> bool:
        value = request.metadata.get("ai_fail_closed")
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def _is_policy_fail_closed_enabled(
        self,
        *,
        for_v2_execution: bool = False,
        request: ScanRequest | None = None,
    ) -> bool:
        if request is not None and self._is_ai_fail_closed_request(request):
            return True
        if not for_v2_execution and not self.is_feature_enabled("plugin_system_v2"):
            return False
        return bool(self._feature_flags.get("policy_fail_closed", True))

    def _resolve_policy_result(
        self,
        *,
        request: ScanRequest,
        for_v2_execution: bool = False,
    ) -> PolicyBuildResult:
        policy_payload: Mapping[str, Any] | None = None
        request_policy = request.metadata.get("policy")
        if isinstance(request_policy, Mapping):
            policy_payload = request_policy
        elif isinstance(self._config.get("policy"), Mapping):
            policy_payload = self._config.get("policy")
        return self._policy_engine.build_policy_result(
            policy_payload,
            fail_closed=self._is_policy_fail_closed_enabled(
                for_v2_execution=for_v2_execution,
                request=request,
            ),
        )

    def _resolve_policy(self, *, request: ScanRequest) -> PluginPolicy:
        return self._resolve_policy_result(request=request).policy
