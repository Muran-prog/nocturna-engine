"""Cache checks for preflight."""

from __future__ import annotations

from typing import Any

from nocturna_engine.core.plugin_v2 import build_result_fingerprint
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


async def resolve_preflight_cache(
    manager: Any,
    *,
    tool_name: str,
    request: ScanRequest,
    registration: Any,
    policy: Any,
    policy_decision: Any,
) -> tuple[str | None, ScanResult | None]:
    """Resolve cache key and return cached result when enabled."""
    cache_key: str | None = None
    if policy.allow_cache:
        cache_key = build_result_fingerprint(
            request=request,
            tool_name=tool_name,
            tool_version=registration.manifest.version,
            policy_signature=policy.model_dump(mode="json"),
        )
        cached = await manager._result_cache.get(cache_key)
        if cached is not None:
            cached.request_id = request.request_id
            cached.tool_name = tool_name
            cached.metadata = {
                **cached.metadata,
                "cache_hit": True,
                "manifest_id": registration.manifest.id,
                "effective_timeout_seconds": policy_decision.effective_timeout_seconds,
                "effective_retries": policy_decision.effective_retries,
                "effective_max_output_bytes": policy_decision.effective_max_output_bytes,
            }
            await manager._event_bus.publish(
                "on_tool_finished",
                {
                    "tool": tool_name,
                    "request_id": request.request_id,
                    "success": cached.success,
                    "duration_ms": cached.duration_ms,
                    "cache_hit": True,
                },
            )
            return cache_key, cached

    return cache_key, None

