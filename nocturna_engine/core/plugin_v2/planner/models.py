"""Explainable AI plan datamodels."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PlanStep:
    """One explainable plan step with fallback options."""

    tool_name: str
    score: float
    reasons: list[str] = field(default_factory=list)
    fallback_tools: list[str] = field(default_factory=list)
    estimated_cost: float = 1.0


@dataclass(slots=True)
class AIPlan:
    """Explainable and machine-readable execution plan."""

    target: str
    goal: str
    mode: str
    steps: list[PlanStep]
    skipped: dict[str, str] = field(default_factory=dict)

    def selected_tools(self) -> list[str]:
        return [step.tool_name for step in self.steps]

    def explain(self) -> str:
        lines = [f"AI plan for target={self.target} goal={self.goal} mode={self.mode}"]
        for index, step in enumerate(self.steps, start=1):
            reason_text = "; ".join(step.reasons) if step.reasons else "no explicit reason"
            fallback = ", ".join(step.fallback_tools) if step.fallback_tools else "none"
            lines.append(
                f"{index}. {step.tool_name} (score={step.score:.2f}, cost={step.estimated_cost:.2f}) "
                f"reasons=[{reason_text}] fallback=[{fallback}]"
            )
        if self.skipped:
            lines.append("Skipped plugins:")
            for name, reason in sorted(self.skipped.items()):
                lines.append(f"- {name}: {reason}")
        return "\n".join(lines)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "goal": self.goal,
            "mode": self.mode,
            "steps": [
                {
                    "tool_name": step.tool_name,
                    "score": step.score,
                    "reasons": list(step.reasons),
                    "fallback_tools": list(step.fallback_tools),
                    "estimated_cost": step.estimated_cost,
                }
                for step in self.steps
            ],
            "skipped": dict(self.skipped),
        }
