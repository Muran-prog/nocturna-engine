"""Setup-failure normalization and payload builders for plugin lifecycle."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.exceptions import build_error_details, error_details_from_exception


class PluginSetupFailureMixin:
    """Helpers for setup failure state and event payload normalization."""

    def _normalize_setup_failure(
        self,
        *,
        tool_name: str,
        setup_failure: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Normalize persisted setup failure payload for results/events."""

        reason = str(setup_failure.get("reason") or "tool_setup_failed")
        reason_code = str(setup_failure.get("reason_code") or reason)
        error_message = str(setup_failure.get("error") or reason)

        details_value = setup_failure.get("error_details")
        if isinstance(details_value, Mapping):
            context_value = details_value.get("context")
            context: dict[str, Any] = {}
            if isinstance(context_value, Mapping):
                context.update({str(key): value for key, value in context_value.items()})
            context.setdefault("tool", tool_name)
            context.setdefault("stage", "setup")

            remediation_value = details_value.get("remediation")
            error_details = build_error_details(
                code=str(details_value.get("code") or reason_code),
                category=str(details_value.get("category") or "plugin_setup"),
                retryable=bool(details_value.get("retryable", False)),
                remediation=str(remediation_value) if isinstance(remediation_value, str) else None,
                context=context,
            )
        else:
            error_details = build_error_details(
                code=reason_code,
                category="plugin_setup",
                retryable=False,
                remediation="Fix plugin setup and dependencies, then retry.",
                context={"tool": tool_name, "stage": "setup"},
            )

        return {
            "tool": tool_name,
            "stage": "setup",
            "error": error_message,
            "reason": reason,
            "reason_code": reason_code,
            "error_details": error_details,
        }

    def _build_setup_failure_state(self, *, tool_name: str, error: BaseException) -> dict[str, Any]:
        """Build structured setup-failure state from setup exception."""

        reason = "tool_setup_failed"
        reason_code = "tool_setup_failed"
        details = error_details_from_exception(
            error,
            default_code=reason_code,
            default_category="plugin_setup",
            default_retryable=False,
            default_remediation="Fix plugin setup and dependencies, then retry.",
            context={"tool": tool_name, "stage": "setup", "error_type": type(error).__name__},
        )
        return self._normalize_setup_failure(
            tool_name=tool_name,
            setup_failure={
                "tool": tool_name,
                "stage": "setup",
                "error": str(error) or reason,
                "reason": reason,
                "reason_code": reason_code,
                "error_details": details,
            },
        )

    def _build_setup_error_event_payload(
        self,
        *,
        tool_name: str,
        setup_failure: Mapping[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Build `on_tool_error` payload for setup failures."""

        normalized = self._normalize_setup_failure(tool_name=tool_name, setup_failure=setup_failure)
        details_value = normalized["error_details"]
        details = (
            dict(details_value)
            if isinstance(details_value, Mapping)
            else build_error_details(
                code=str(normalized["reason_code"]),
                category="plugin_setup",
                context={"tool": tool_name, "stage": "setup"},
            )
        )
        context_value = details.get("context")
        context = dict(context_value) if isinstance(context_value, Mapping) else {"tool": tool_name, "stage": "setup"}

        payload: dict[str, Any] = {
            "tool": tool_name,
            "error": str(normalized["error"]),
            "stage": "setup",
            "reason": str(normalized["reason"]),
            "reason_code": str(normalized["reason_code"]),
            "error_details": details,
            "code": str(details.get("code") or normalized["reason_code"]),
            "category": str(details.get("category") or "plugin_setup"),
            "retryable": bool(details.get("retryable", False)),
            "remediation": details.get("remediation"),
            "context": context,
        }
        if request_id is not None:
            payload["request_id"] = request_id
        return payload

    def _get_tool_setup_failure(self, tool_name: str) -> dict[str, Any] | None:
        """Return normalized setup-failure state for a tool."""

        existing = self._tool_setup_failures.get(tool_name)
        if existing is None:
            return None
        return self._normalize_setup_failure(tool_name=tool_name, setup_failure=existing)

    def _clear_tool_setup_failure(self, tool_name: str) -> None:
        """Clear persisted setup-failure state for a tool."""

        self._tool_setup_failures.pop(tool_name, None)
