"""Pipeline type aliases."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

PipelineContext = dict[str, Any]
StepHandler = Callable[[PipelineContext], Awaitable[PipelineContext | None]]
StepCondition = Callable[[PipelineContext], bool]
