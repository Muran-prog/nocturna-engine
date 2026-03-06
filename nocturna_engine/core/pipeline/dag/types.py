from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal

from nocturna_engine.core.pipeline.types import PipelineContext

PhaseStepStatus = Literal["pending", "running", "succeeded", "failed", "skipped"]
PhaseToolHandler = Callable[["PhaseStep", PipelineContext], Awaitable[PipelineContext | None]]

_TERMINAL_STATUSES: frozenset[PhaseStepStatus] = frozenset({"succeeded", "failed", "skipped"})
