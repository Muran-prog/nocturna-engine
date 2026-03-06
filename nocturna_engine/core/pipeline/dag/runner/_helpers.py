from __future__ import annotations

from nocturna_engine.core.pipeline.dag.step import PhaseStep
from nocturna_engine.core.pipeline.dag.types import (
    PhaseStepStatus,
    _TERMINAL_STATUSES,
)


class RunnerHelpersMixin:
    """Pure static helpers for dependency checks and phase grouping."""

    @staticmethod
    def _dependencies_completed(step: PhaseStep, statuses: dict[str, PhaseStepStatus]) -> bool:
        return all(statuses[dep] in _TERMINAL_STATUSES for dep in step.deps)

    @staticmethod
    def _group_steps_by_phase(steps: list[PhaseStep]) -> dict[str, list[PhaseStep]]:
        grouped: dict[str, list[PhaseStep]] = {}
        for step in steps:
            grouped.setdefault(step.phase, []).append(step)
        return grouped

    @staticmethod
    def _build_phase_statuses(
        phase_to_steps: dict[str, list[PhaseStep]],
        statuses: dict[str, PhaseStepStatus],
    ) -> dict[str, PhaseStepStatus]:
        phase_statuses: dict[str, PhaseStepStatus] = {}
        for phase, items in phase_to_steps.items():
            values = [statuses[step.id] for step in items]
            if any(value == "failed" for value in values):
                phase_statuses[phase] = "failed"
                continue
            if all(value == "skipped" for value in values):
                phase_statuses[phase] = "skipped"
                continue
            if all(value == "succeeded" for value in values):
                phase_statuses[phase] = "succeeded"
                continue
            if any(value == "running" for value in values):
                phase_statuses[phase] = "running"
                continue
            phase_statuses[phase] = "pending"
        return phase_statuses
