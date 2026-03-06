from __future__ import annotations

from typing import Any

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.core.pipeline.dag.runner._events import RunnerEventsMixin
from nocturna_engine.core.pipeline.dag.runner._execution import RunnerExecutionMixin
from nocturna_engine.core.pipeline.dag.runner._helpers import RunnerHelpersMixin
from nocturna_engine.core.pipeline.dag.runner._validation import RunnerValidationMixin


class PhaseDAGRunner(
    RunnerExecutionMixin,
    RunnerEventsMixin,
    RunnerHelpersMixin,
    RunnerValidationMixin,
):
    """Execute phase DAG nodes when all dependencies are completed."""

    def __init__(
        self,
        *,
        logger: BoundLogger | None = None,
        event_bus: Any | None = None,
        concurrency_limit: int = 4,
    ) -> None:
        self._logger = logger or structlog.get_logger("phase_dag_runner")
        self._event_bus = event_bus
        self._concurrency_limit = max(1, concurrency_limit)
