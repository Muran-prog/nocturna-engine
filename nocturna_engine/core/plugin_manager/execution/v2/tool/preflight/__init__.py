"""Preflight stage for v2 single-tool execution."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult

from ..models import ToolPreflightState
from .adapter import resolve_preflight_adapter
from .cache import resolve_preflight_cache
from .circuit import check_preflight_circuit
from .policy import resolve_preflight_policy


async def run_tool_preflight(
    manager: Any,
    *,
    tool_name: str,
    request: ScanRequest,
    started_at: datetime,
    registration: Any,
) -> tuple[ToolPreflightState | None, ScanResult | None]:
    """Resolve policy/cache/adapter and return execution state or early result."""
    policy, policy_decision, early_result = await resolve_preflight_policy(
        manager,
        tool_name=tool_name,
        request=request,
        started_at=started_at,
        registration=registration,
    )
    if early_result is not None:
        return None, early_result

    circuit_failure = await check_preflight_circuit(
        manager,
        tool_name=tool_name,
        request=request,
        started_at=started_at,
    )
    if circuit_failure is not None:
        return None, circuit_failure

    cache_key, cached_result = await resolve_preflight_cache(
        manager,
        tool_name=tool_name,
        request=request,
        registration=registration,
        policy=policy,
        policy_decision=policy_decision,
    )
    if cached_result is not None:
        return None, cached_result

    adapter, early_result = await resolve_preflight_adapter(
        manager,
        tool_name=tool_name,
        request=request,
        started_at=started_at,
    )
    if early_result is not None:
        return None, early_result

    dispatch_failure = await manager._validate_dispatch_constraints(
        tool_name=tool_name,
        tool=adapter.tool,
        request=request,
        started_at=started_at,
        policy=policy,
    )
    if dispatch_failure is not None:
        return None, dispatch_failure

    return (
        ToolPreflightState(
            registration=registration,
            policy=policy,
            policy_decision=policy_decision,
            adapter=adapter,
            cache_key=cache_key,
        ),
        None,
    )
