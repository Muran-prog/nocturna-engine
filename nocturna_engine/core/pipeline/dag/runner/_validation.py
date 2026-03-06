from __future__ import annotations

from nocturna_engine.core.pipeline.dag.step import PhaseStep
from nocturna_engine.exceptions import PipelineError


class RunnerValidationMixin:
    """DAG structural validation: indexing, dependency checks, cycle detection."""

    @staticmethod
    def _index_steps(steps: list[PhaseStep]) -> dict[str, PhaseStep]:
        indexed: dict[str, PhaseStep] = {}
        duplicates: set[str] = set()
        for step in steps:
            if step.id in indexed:
                duplicates.add(step.id)
            indexed[step.id] = step
        if duplicates:
            duplicates_text = ", ".join(sorted(duplicates))
            raise PipelineError(f"Duplicate phase step ids in DAG: {duplicates_text}")
        return indexed

    @staticmethod
    def _validate_dependencies(steps_by_id: dict[str, PhaseStep]) -> None:
        missing: list[tuple[str, str]] = []
        for step in steps_by_id.values():
            for dep in step.deps:
                if dep not in steps_by_id:
                    missing.append((step.id, dep))
        if missing:
            details = ", ".join(f"{step_id}->{dep}" for step_id, dep in missing)
            raise PipelineError(f"Phase DAG has unknown dependencies: {details}")

    @staticmethod
    def _assert_acyclic(steps_by_id: dict[str, PhaseStep]) -> None:
        state: dict[str, int] = {}
        
        for start_id in steps_by_id:
            if state.get(start_id, 0) != 0:
                continue
            call_stack: list[tuple[str, int]] = [(start_id, 0)]
            path: list[str] = []
            while call_stack:
                node_id, dep_idx = call_stack[-1]
                if state.get(node_id, 0) == 0:
                    state[node_id] = 1
                    path.append(node_id)
                deps = steps_by_id[node_id].deps
                if dep_idx < len(deps):
                    call_stack[-1] = (node_id, dep_idx + 1)
                    dep = deps[dep_idx]
                    marker = state.get(dep, 0)
                    if marker == 2:
                        continue
                    if marker == 1:
                        cycle_start = path.index(dep) if dep in path else 0
                        cycle = path[cycle_start:] + [dep]
                        raise PipelineError(f"Cycle detected in phase DAG: {' -> '.join(cycle)}")
                    call_stack.append((dep, 0))
                else:
                    state[node_id] = 2
                    if path and path[-1] == node_id:
                        path.pop()
                    call_stack.pop()
