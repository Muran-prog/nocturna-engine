"""Path normalization and egress-policy helpers for BaseApiTool."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from nocturna_engine.core.plugin_v2 import EgressPolicyEvaluator, PluginPolicy

from ..errors import ApiEgressPolicyError, ApiOriginError


class ApiPathPolicyMixin:
    """Mixin with request path and egress policy enforcement logic."""

    def _resolve_runtime_policy(self) -> PluginPolicy | None:
        context = self._runtime_context
        if context is None:
            return None

        policy_payload = getattr(context, "policy", None)
        if not isinstance(policy_payload, Mapping):
            return None

        filtered_payload = {
            field_name: policy_payload[field_name]
            for field_name in PluginPolicy.model_fields.keys()
            if field_name in policy_payload
        }
        if not filtered_payload:
            return None

        try:
            return PluginPolicy.model_validate(filtered_payload)
        except Exception:
            return None

    def _enforce_egress_policy(self, *, request_path: str) -> None:
        policy = self._resolve_runtime_policy()
        if policy is None:
            return

        evaluator = EgressPolicyEvaluator(policy)
        if not evaluator.is_configured:
            return

        config = self._require_api_config()
        parsed_origin = urlsplit(config.base_url)
        protocol, host, port = self._origin_signature(parsed_origin)
        decision = evaluator.evaluate(
            host=host or None,
            port=port,
            protocol=protocol or None,
            source="base_api_tool",
        )
        if decision.allowed:
            return

        context = decision.as_context()
        context.update(
            {
                "request_path": self._sanitize_path_for_log(request_path),
                "tool": self.name,
            }
        )
        raise ApiEgressPolicyError(
            f"Egress policy denied API request to {self._origin_for_log(parsed_origin)}.",
            code=decision.reason_code or "policy_denied_egress",
            category="policy",
            retryable=False,
            remediation="Adjust policy egress rules or API base_url.",
            context=context,
        )

    def _normalize_path(self, path: str) -> str:
        """Normalize request path while enforcing base_url origin restrictions."""

        normalized = str(path or "").strip()
        if not normalized:
            return "/"

        parsed = urlsplit(normalized)
        if parsed.scheme and parsed.netloc:
            return self._normalize_absolute_path(parsed)

        if not normalized.startswith("/"):
            return f"/{normalized}"
        return normalized

    def _normalize_absolute_path(self, parsed_absolute: Any) -> str:
        """Normalize absolute URL into request path if origin is allowed."""

        config = self._require_api_config()
        allowed_origin = urlsplit(config.base_url)
        requested_origin = parsed_absolute

        if self._origin_signature(requested_origin) != self._origin_signature(allowed_origin):
            allowed_origin_label = self._origin_for_log(allowed_origin)
            requested_origin_label = self._origin_for_log(requested_origin)
            self.logger.warning(
                "api_request_disallowed_origin",
                allowed_origin=allowed_origin_label,
                requested_origin=requested_origin_label,
                path=self._sanitize_path_for_log(parsed_absolute.geturl()),
            )
            raise ApiOriginError(
                "Cross-origin absolute URL is not allowed for this API client "
                f"(requested_origin={requested_origin_label}, allowed_origin={allowed_origin_label})."
            )

        request_path = parsed_absolute.path or "/"
        if parsed_absolute.query:
            request_path = f"{request_path}?{parsed_absolute.query}"
        return request_path

    @staticmethod
    def _origin_signature(parsed_url: Any) -> tuple[str, str, int | None]:
        """Build normalized (scheme, host, port) origin tuple."""

        scheme = str(parsed_url.scheme or "").lower()
        host = str(parsed_url.hostname or "").lower()
        port = parsed_url.port
        if port is None:
            if scheme == "http":
                port = 80
            elif scheme == "https":
                port = 443
        return scheme, host, port

    @staticmethod
    def _origin_for_log(parsed_url: Any) -> str:
        """Render origin label without path/query/fragment data."""

        scheme, host, port = ApiPathPolicyMixin._origin_signature(parsed_url)
        if not scheme or not host:
            return "unknown"

        default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
        if port is None or port == default_port:
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    @staticmethod
    def _sanitize_path_for_log(path: str) -> str:
        """Sanitize path for logs by stripping query params.

        Args:
            path: Raw request path.

        Returns:
            str: Query-free request path.
        """

        parsed = urlsplit(path)
        cleaned = parsed.path or "/"
        return cleaned[:512]
