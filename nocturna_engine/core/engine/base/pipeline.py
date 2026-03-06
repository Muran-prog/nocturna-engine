"""Default pipeline composition for Nocturna Engine."""

from __future__ import annotations

from nocturna_engine.core.pipeline import PipelineStep


class _EnginePipelineMixin:
    def _configure_default_pipeline(self) -> None:
        """Configure default scan -> analyze -> report pipeline."""

        self.pipeline.clear_steps()
        self.pipeline.add_step(
            PipelineStep(
                name="scan",
                handler=self._scan_step,
                timeout_seconds=90.0,
                retries=1,
                continue_on_error=False,
            )
        )
        self.pipeline.add_step(
            PipelineStep(
                name="analyze",
                handler=self._analyze_step,
                condition=lambda ctx: bool(ctx.get("scan_results")),
                timeout_seconds=60.0,
                retries=1,
                continue_on_error=True,
            )
        )
        self.pipeline.add_step(
            PipelineStep(
                name="report",
                handler=self._report_step,
                timeout_seconds=45.0,
                retries=1,
                continue_on_error=True,
            )
        )
