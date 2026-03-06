"""Pipeline step descriptors."""

from __future__ import annotations

from dataclasses import dataclass

from nocturna_engine.core.pipeline.types import StepCondition, StepHandler


@dataclass(slots=True)
class PipelineStep:
    """Describes one pipeline step.

    Attributes:
        name: Unique step name.
        handler: Async callable receiving current context.
        condition: Optional predicate controlling execution.
        parallel_group: Group key for parallel execution.
        timeout_seconds: Timeout for this step.
        retries: Retry count for this step.
        continue_on_error: Whether errors should be logged and ignored.
    """

    name: str
    handler: StepHandler
    condition: StepCondition | None = None
    parallel_group: str | None = None
    timeout_seconds: float = 30.0
    retries: int = 1
    continue_on_error: bool = True
