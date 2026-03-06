"""Composed AI mixin for engine orchestration."""

from __future__ import annotations

from typing import Any

from .constants import _FAST_POLICY_PROFILE, _SAFE_POLICY_PROFILE
from .planning import _EngineAIPlanningMixin


class _EngineAIMixin(_EngineAIPlanningMixin):
    _SAFE_POLICY_PROFILE: dict[str, Any] = dict(_SAFE_POLICY_PROFILE)
    _FAST_POLICY_PROFILE: dict[str, Any] = dict(_FAST_POLICY_PROFILE)

    @staticmethod
    def _policy_from_safe_flag(safe: bool | None) -> dict[str, Any]:
        if safe is None:
            return {}
        if safe:
            return dict(_EngineAIMixin._SAFE_POLICY_PROFILE)
        return dict(_EngineAIMixin._FAST_POLICY_PROFILE)
