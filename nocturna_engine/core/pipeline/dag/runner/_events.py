from __future__ import annotations

from typing import Any

from structlog.stdlib import BoundLogger

from nocturna_engine.core.pipeline.dag.step import PhaseStep
from nocturna_engine.core.pipeline.dag.types import (
    PhaseStepStatus,
    _TERMINAL_STATUSES,
)
from nocturna_engine.core.pipeline.types import PipelineContext


class RunnerEventsMixin:
    """Event bus integration: emit lifecycle events and finalize phases."""

    _logger: BoundLogger
    _event_bus: Any | None

    # -- imported from _helpers via MRO --
    _build_phase_statuses: Any

    async def _finalize_phase_if_ready(
        self,
        *,
        phase: str,
        phase_to_steps: dict[str, list[PhaseStep]],
        statuses: dict[str, PhaseStepStatus],
        finalized_phases: set[str],
        failed_phases: set[str],
        context: PipelineContext,
    ) -> None:
        if phase in finalized_phases:
            return

        current_steps = phase_to_steps.get(phase, [])
        if not current_steps:
            finalized_phases.add(phase)
            return

        if not all(statuses[step.id] in _TERMINAL_STATUSES for step in current_steps):
            return

        finalized_phases.add(phase)
        phase_status = self._build_phase_statuses(
            {phase: current_steps},
            statuses,
        )[phase]
        if phase_status in {"failed", "running", "pending"} or phase in failed_phases:
            return

        await self._emit(
            "on_phase_finished",
            self._build_phase_payload(
                context=context,
                phase=phase,
                extra={
                    "status": phase_status,
                    "step_count": len(current_steps),
                },
            ),
        )

    def _build_phase_payload(
        self,
        *,
        context: PipelineContext,
        phase: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"phase": phase}
        request = context.get("request")
        request_id = getattr(request, "request_id", None)
        if request_id is not None:
            payload["request_id"] = request_id
        if extra:
            payload.update(extra)
        return payload

    async def _emit(self, event_name: str, payload: dict[str, Any]) -> None:
        if self._event_bus is None:
            return
        publish = getattr(self._event_bus, "publish", None)
        if not callable(publish):
            return
        try:
            await publish(event_name, payload)
        except Exception as exc:
            self._logger.warning(
                "phase_event_publish_failed",
                event_name=event_name,
                error=str(exc),
            )
