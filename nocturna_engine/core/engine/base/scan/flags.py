"""Feature flags and token normalization helpers for scan orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nocturna_engine.models.scan_request import ScanRequest

from .constants import _PHASE_ALIASES, _PHASE_SEQUENCE


class _EngineScanFeatureFlagsMixin:
    def _is_phase_dag_enabled(self, request: ScanRequest) -> bool:
        explicit_flag = request.metadata.get("use_phase_dag")
        if explicit_flag is None:
            explicit_flag = request.metadata.get("dag_enabled")
        if explicit_flag is not None:
            return self._coerce_bool(explicit_flag)

        features = self._config.get("features", {})
        if isinstance(features, Mapping):
            return self._coerce_bool(features.get("phase_dag_pipeline", False))
        return False

    @staticmethod
    def _canonicalize_phase_token(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower()
        if not normalized:
            return None
        if normalized in _PHASE_SEQUENCE:
            return normalized
        for phase, aliases in _PHASE_ALIASES.items():
            if normalized in aliases:
                return phase
        return None

    @staticmethod
    def _coerce_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "y", "on"}:
                return True
            if normalized in {"0", "false", "no", "n", "off"}:
                return False
        return bool(value)
