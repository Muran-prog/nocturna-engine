"""Pipeline runner implementation."""

from __future__ import annotations

from typing import Awaitable, Callable

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.core.pipeline.step import PipelineStep
from nocturna_engine.core.pipeline.types import PipelineContext
from nocturna_engine.exceptions import PipelineError
from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, bounded_gather, retry_async, with_timeout


class Pipeline:
    """Run an ordered chain of async steps with branching."""

    def __init__(self, logger: BoundLogger | None = None) -> None:
        """Initialize pipeline.

        Args:
            logger: Optional logger.
        """

        self._logger = logger or structlog.get_logger("pipeline")
        self._steps: list[PipelineStep] = []

    def add_step(self, step: PipelineStep) -> None:
        """Append one step to the pipeline.

        Args:
            step: Pipeline step descriptor.
        """

        self._steps.append(step)

    def clear_steps(self) -> None:
        """Remove all configured steps."""

        self._steps.clear()

    def list_steps(self) -> list[str]:
        """Return step names in execution order.

        Returns:
            list[str]: Ordered step names.
        """

        return [step.name for step in self._steps]

    async def run(self, initial_context: PipelineContext | None = None) -> PipelineContext:
        """Execute configured pipeline.

        Args:
            initial_context: Optional initial context.

        Returns:
            PipelineContext: Final context object.

        Raises:
            PipelineError: If a required step fails.
        """

        context: PipelineContext = dict(initial_context or {})
        context.setdefault("errors", [])

        index = 0
        while index < len(self._steps):
            step = self._steps[index]
            if step.parallel_group:
                group, next_index = self._collect_parallel_group(index)
                context = await self._run_parallel_group(group, context)
                index = next_index
                continue
            context = await self._run_single_step(step, context)
            index += 1

        return context

    def _collect_parallel_group(self, start_index: int) -> tuple[list[PipelineStep], int]:
        """Collect consecutive steps in the same parallel group.

        Args:
            start_index: First step index.

        Returns:
            tuple[list[PipelineStep], int]: Group steps and next index.
        """

        first = self._steps[start_index]
        group_name = first.parallel_group
        index = start_index
        group: list[PipelineStep] = []
        while index < len(self._steps):
            current = self._steps[index]
            if current.parallel_group != group_name:
                break
            group.append(current)
            index += 1
        return group, index

    async def _run_parallel_group(
        self,
        steps: list[PipelineStep],
        context: PipelineContext,
    ) -> PipelineContext:
        """Execute group of steps concurrently.

        Args:
            steps: Steps in one parallel group.
            context: Current pipeline context.

        Returns:
            PipelineContext: Updated context.
        """

        eligible: list[PipelineStep] = []
        for step in steps:
            should_run, context = self._should_run_with_policy(step, context)
            if should_run:
                eligible.append(step)
        if not eligible:
            return context

        snapshot = dict(context)
        factories = [self._build_step_factory(step, snapshot) for step in eligible]
        results = await bounded_gather(
            factories,
            concurrency_limit=max(1, len(factories)),
            return_exceptions=True,
        )

        for step, result in zip(eligible, results):
            if isinstance(result, BaseException):
                context = self._handle_step_failure(step, context, result)
                continue
            for key, value in result.items():
                if key not in ("errors", "request", "artifacts"):
                    context[key] = value
        return context

    def _build_step_factory(
        self, step: PipelineStep, context: PipelineContext
    ) -> Callable[[], Awaitable[PipelineContext]]:
        """Build one deferred step invocation.

        Args:
            step: Step descriptor.
            context: Context snapshot for this step.

        Returns:
            Callable[[], Awaitable[PipelineContext]]: Async callable operation.
        """

        async def _operation() -> PipelineContext:
            return await self._invoke_step(step, dict(context))

        return _operation

    async def _run_single_step(self, step: PipelineStep, context: PipelineContext) -> PipelineContext:
        """Execute one step and merge produced context.

        Args:
            step: Step descriptor.
            context: Current pipeline context.

        Returns:
            PipelineContext: Updated context.
        """

        should_run, context = self._should_run_with_policy(step, context)
        if not should_run:
            return context
        try:
            update = await self._invoke_step(step, dict(context))
            context.update(update)
            return context
        except Exception as exc:
            return self._handle_step_failure(step, context, exc)

    async def _invoke_step(self, step: PipelineStep, context: PipelineContext) -> PipelineContext:
        """Invoke step handler with timeout and retry.

        Args:
            step: Step descriptor.
            context: Step input context.

        Returns:
            PipelineContext: Step output context.

        Raises:
            PipelineError: If step returns invalid output.
        """

        async def _handler() -> PipelineContext:
            result = await with_timeout(
                step.handler(context),
                timeout_seconds=step.timeout_seconds,
                operation_name=f"pipeline_step:{step.name}",
            )
            if result is None:
                return {}
            if not isinstance(result, dict):
                raise PipelineError(f"Step '{step.name}' must return dict or None.")
            return result

        return await retry_async(
            _handler,
            retries=step.retries,
            retry_exceptions=TRANSIENT_RETRY_EXCEPTIONS,
        )

    @staticmethod
    def _should_run(step: PipelineStep, context: PipelineContext) -> bool:
        """Evaluate optional step condition.

        Args:
            step: Step descriptor.
            context: Current pipeline context.

        Returns:
            bool: True if step should execute.
        """

        if step.condition is None:
            return True
        return bool(step.condition(context))

    def _should_run_with_policy(
        self,
        step: PipelineStep,
        context: PipelineContext,
    ) -> tuple[bool, PipelineContext]:
        """Evaluate condition and apply step failure policy on condition errors.

        Args:
            step: Step descriptor.
            context: Current pipeline context.

        Returns:
            tuple[bool, PipelineContext]: Condition decision and current context.
        """

        try:
            return self._should_run(step, context), context
        except Exception as exc:
            condition_error = RuntimeError(
                f"Condition for step '{step.name}' raised {type(exc).__name__}: {exc}"
            )
            return False, self._handle_step_failure(step, context, condition_error)

    def _handle_step_failure(
        self,
        step: PipelineStep,
        context: PipelineContext,
        error: BaseException,
    ) -> PipelineContext:
        """Handle one step failure according to step policy.

        Args:
            step: Failed step.
            context: Pipeline context.
            error: Raised exception.

        Returns:
            PipelineContext: Updated context.

        Raises:
            PipelineError: If step is not allowed to continue on failure.
        """

        if step.continue_on_error:
            context.setdefault("errors", []).append({"step": step.name, "error": str(error)})
            self._logger.warning("pipeline_step_failed", step=step.name, error=str(error))
            return context
        raise PipelineError(f"Pipeline step '{step.name}' failed: {error}") from error
