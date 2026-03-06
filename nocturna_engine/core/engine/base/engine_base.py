"""Composed base class for Nocturna Engine orchestration."""

from __future__ import annotations

from .lifecycle import _EngineLifecycleMixin
from .pipeline import _EnginePipelineMixin
from .scan import _EngineScanMixin
from .ai import _EngineAIMixin


class _EngineBase(
    _EngineLifecycleMixin,
    _EngineScanMixin,
    _EngineAIMixin,
    _EnginePipelineMixin,
):
    """Base orchestration lifecycle and API for Nocturna Engine."""
