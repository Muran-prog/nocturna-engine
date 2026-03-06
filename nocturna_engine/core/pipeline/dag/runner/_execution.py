from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from structlog.stdlib import BoundLogger

from nocturna_engine.core.pipeline.artifacts import ArtifactStore
from nocturna_engine.core.pipeline.dag.step import PhaseStep
from nocturna_engine.core.pipeline.dag.types import (
    PhaseStepStatus,
    PhaseToolHandler,
    _TERMINAL_STATUSES,
)
from nocturna_engine.core.pipeline.types import PipelineContext
from nocturna_engine.exceptions import PipelineError
from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, bounded_gather, retry_async, with_timeout


class RunnerExecutionMixin:
    """Core DAG execution loop and step invocation."""

    _logger: BoundLogger
    _event_bus: Any | None
    _concurrency_limit: int

    # -- imported from other mixins via MRO --
    _index_steps: Any
    _validate_dependencies: Any
    _assert_acyclic: Any
    _dependencies_completed: Any
    _group_steps_by_phase: Any
    _build_phase_statuses: Any
    _emit: Any
    _build_phase_payload: Any
    _finalize_phase_if_ready: Any

    async def run(
        self,
        steps: list[PhaseStep],
        *,
        tool_handler: PhaseToolHandler,
        initial_context: PipelineContext | None = None,
    ) -> PipelineContext:
        """Run full DAG and return updated context."""

        context: PipelineContext = PipelineContext(initial_context or {})
        context.setdefault("errors", [])
        if not isinstance(context.get("artifacts"), ArtifactStore):
            context["artifacts"] = ArtifactStore()

        ordered_steps = list(steps)
        if not ordered_steps:
            context["dag_step_status"] = {}
            context["dag_phase_status"] = {}
            context["dag_skip_reasons"] = {}
            return context

        steps_by_id = self._index_steps(ordered_steps)
        self._validate_dependencies(steps_by_id)
        self._assert_acyclic(steps_by_id)

        statuses: dict[str, PhaseStepStatus] = {step.id: "pending" for step in ordered_steps}
        skip_reasons: dict[str, str] = {}
        phase_to_steps = self._group_steps_by_phase(ordered_steps)
        started_phases: set[str] = set()
        finalized_phases: set[str] = set()
        failed_phases: set[str] = set()

        while True:
            pending_steps = [step for step in ordered_steps if statuses[step.id] == "pending"]
            if not pending_steps:
                break

            ready_steps = [step for step in pending_steps if self._dependencies_completed(step, statuses)]
            if not ready_steps:
                unresolved = {
                    step.id: [dep for dep in step.deps if statuses[dep] not in _TERMINAL_STATUSES]
                    for step in pending_steps
                }
                raise PipelineError(
                    "Phase DAG execution stalled due to unresolved dependencies: "
                    f"{unresolved}"
                )

            # ---- partition: skippable vs executable --------------------------
            skippable: list[PhaseStep] = []
            executable: list[PhaseStep] = []
            for step in ready_steps:
                if any(statuses[dep] in {"failed", "skipped"} for dep in step.deps):
                    skippable.append(step)
                else:
                    executable.append(step)

            # ---- handle skippable synchronously -----------------------------
            for step in skippable:
                statuses[step.id] = "skipped"
                dep_snapshot = {dep: statuses[dep] for dep in step.deps}
                skip_reasons[step.id] = f"dependency_failed_or_skipped:{dep_snapshot}"
                self._logger.info(
                    "phase_step_skipped",
                    step_id=step.id,
                    phase=step.phase,
                    tool=step.tool,
                    dependencies=dep_snapshot,
                )
                await self._finalize_phase_if_ready(
                    phase=step.phase,
                    phase_to_steps=phase_to_steps,
                    statuses=statuses,
                    finalized_phases=finalized_phases,
                    failed_phases=failed_phases,
                    context=context,
                )

            if not executable:
                continue

            # ---- emit on_phase_started for new phases -----------------------
            for step in executable:
                if step.phase not in started_phases:
                    started_phases.add(step.phase)
                    await self._emit(
                        "on_phase_started",
                        self._build_phase_payload(
                            context=context,
                            phase=step.phase,
                            extra={"step_id": step.id, "tool": step.tool},
                        ),
                    )
                statuses[step.id] = "running"

            # ---- execute ready steps in parallel ----------------------------
            factories: list[Callable[[], Awaitable[dict[str, Any]]]] = [
                self._build_dag_step_factory(step=step, context=context.deep_snapshot(), tool_handler=tool_handler)
                for step in executable
            ]
            results = await bounded_gather(
                factories,
                concurrency_limit=min(self._concurrency_limit, len(factories)),
                return_exceptions=True,
            )

            # ---- reconcile results ------------------------------------------
            for step, result in zip(executable, results):
                if isinstance(result, BaseException):
                    statuses[step.id] = "failed"
                    is_first_phase_failure = step.phase not in failed_phases
                    failed_phases.add(step.phase)
                    context["errors"].append(
                        {
                            "step": step.id,
                            "phase": step.phase,
                            "tool": step.tool,
                            "error": str(result),
                        }
                    )
                    self._logger.warning(
                        "phase_step_failed",
                        step_id=step.id,
                        phase=step.phase,
                        tool=step.tool,
                        error=str(result),
                    )
                    if is_first_phase_failure:
                        await self._emit(
                            "on_phase_failed",
                            self._build_phase_payload(
                                context=context,
                                phase=step.phase,
                                extra={"step_id": step.id, "tool": step.tool, "error": str(result)},
                            ),
                        )
                else:
                    statuses[step.id] = "succeeded"
                    context.merge_from(result)
                    self._logger.info(
                        "phase_step_succeeded",
                        step_id=step.id,
                        phase=step.phase,
                        tool=step.tool,
                    )

                await self._finalize_phase_if_ready(
                    phase=step.phase,
                    phase_to_steps=phase_to_steps,
                    statuses=statuses,
                    finalized_phases=finalized_phases,
                    failed_phases=failed_phases,
                    context=context,
                )

        context["dag_step_status"] = dict(statuses)
        context["dag_phase_status"] = self._build_phase_statuses(phase_to_steps, statuses)
        context["dag_skip_reasons"] = dict(skip_reasons)
        return context

    def _build_dag_step_factory(
        self,
        *,
        step: PhaseStep,
        context: PipelineContext,
        tool_handler: PhaseToolHandler,
    ) -> Callable[[], Awaitable[dict[str, Any]]]:
        """Build a deferred invocation for one DAG step."""

        async def _operation() -> dict[str, Any]:
            return await self._invoke_step(step=step, context=context, tool_handler=tool_handler)

        return _operation

    async def _invoke_step(
        self,
        *,
        step: PhaseStep,
        context: PipelineContext,
        tool_handler: PhaseToolHandler,
    ) -> PipelineContext:
        async def _operation() -> PipelineContext:
            result = await with_timeout(
                tool_handler(step, context),
                timeout_seconds=step.timeout_seconds,
                operation_name=f"phase_step:{step.id}",
            )
            if result is None:
                return {}
            if not isinstance(result, dict):
                raise PipelineError(f"Phase step '{step.id}' must return dict or None.")
            return result

        return await retry_async(
            _operation,
            retries=step.retries,
            retry_exceptions=TRANSIENT_RETRY_EXCEPTIONS,
        )
