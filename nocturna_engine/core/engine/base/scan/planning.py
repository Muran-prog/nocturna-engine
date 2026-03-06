"""Phase DAG step planning for scan orchestration."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from nocturna_engine.core.pipeline import PhaseStep
from nocturna_engine.models.scan_request import ScanRequest

from .constants import _PHASE_SEQUENCE


class _EngineScanPlanningMixin:
    def _build_phase_dag_steps(self, request: ScanRequest) -> list[PhaseStep]:
        available_tools = self.plugin_manager.list_registered_tools()
        available_set = set(available_tools)
        selected = request.tool_names or available_tools
        selected_tools = [name for name in selected if name in available_set]

        if not selected_tools:
            return []

        phase_filter = self._resolve_requested_dag_phases(request)
        descriptions = self.plugin_manager.describe_all_tools(machine_readable=True)
        phase_groups: dict[str, list[PhaseStep]] = {phase: [] for phase in _PHASE_SEQUENCE}

        for tool_name in selected_tools:
            descriptor = descriptions.get(tool_name, {})
            phase = self._resolve_phase_for_tool(
                descriptor=descriptor if isinstance(descriptor, Mapping) else {},
                allowed_phases=phase_filter,
            )
            if phase is None:
                continue
            phase_groups[phase].append(
                PhaseStep(
                    id=f"{phase}.{tool_name}",
                    phase=phase,
                    tool=tool_name,
                    timeout_seconds=request.timeout_seconds,
                    retries=request.retries,
                )
            )

        ordered: list[PhaseStep] = []
        previous_phase_ids: tuple[str, ...] = ()
        for phase in _PHASE_SEQUENCE:
            if phase not in phase_filter:
                continue
            current_steps = phase_groups.get(phase, [])
            if not current_steps:
                continue
            for step in current_steps:
                ordered.append(
                    PhaseStep(
                        id=step.id,
                        phase=step.phase,
                        deps=previous_phase_ids,
                        tool=step.tool,
                        timeout_seconds=step.timeout_seconds,
                        retries=step.retries,
                    )
                )
            previous_phase_ids = tuple(step.id for step in current_steps)

        return ordered

    def _resolve_phase_for_tool(
        self,
        *,
        descriptor: Mapping[str, Any],
        allowed_phases: tuple[str, ...],
    ) -> str | None:
        supported_phases = descriptor.get("supported_phases", [])
        if isinstance(supported_phases, tuple | list):
            for raw_phase in supported_phases:
                canonical = self._canonicalize_phase_token(raw_phase)
                if canonical is not None and canonical in allowed_phases:
                    return canonical

        phase_votes: dict[str, int] = {phase: 0 for phase in _PHASE_SEQUENCE}
        capabilities = descriptor.get("capabilities", [])
        if isinstance(capabilities, tuple | list):
            for item in capabilities:
                tokens: list[Any] = []
                if isinstance(item, Mapping):
                    tokens.extend([item.get("name"), item.get("category")])
                    tags = item.get("tags")
                    if isinstance(tags, tuple | list | set):
                        tokens.extend(list(tags))
                elif isinstance(item, str):
                    tokens.append(item)

                for token in tokens:
                    canonical = self._canonicalize_phase_token(token)
                    if canonical is None:
                        continue
                    phase_votes[canonical] += 1

        best_phase: str | None = None
        best_votes = 0
        for phase in _PHASE_SEQUENCE:
            votes = phase_votes[phase]
            if phase not in allowed_phases or votes <= best_votes:
                continue
            best_votes = votes
            best_phase = phase
        if best_phase is not None:
            return best_phase

        if "validate" in allowed_phases:
            return "validate"
        return allowed_phases[0] if allowed_phases else None

    def _resolve_requested_dag_phases(self, request: ScanRequest) -> tuple[str, ...]:
        requested_raw = request.metadata.get("dag_phases")
        if requested_raw is None:
            requested_raw = request.metadata.get("phases")

        if requested_raw is None:
            ai_plan = request.metadata.get("ai_plan")
            if isinstance(ai_plan, Mapping):
                requested_raw = ai_plan.get("goal")

        tokens: list[str] = []
        if isinstance(requested_raw, str):
            tokens = [item for item in re.split(r"[\s,;+]+", requested_raw) if item]
        elif isinstance(requested_raw, tuple | list | set):
            for item in requested_raw:
                candidate = str(item).strip()
                if candidate:
                    tokens.append(candidate)

        selected: set[str] = set()
        for token in tokens:
            canonical = self._canonicalize_phase_token(token)
            if canonical is not None:
                selected.add(canonical)

        if not selected:
            return _PHASE_SEQUENCE
        return tuple(phase for phase in _PHASE_SEQUENCE if phase in selected)

