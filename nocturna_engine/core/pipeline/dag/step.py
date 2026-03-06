from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PhaseStep:
    """One DAG node bound to a canonical execution phase."""

    id: str
    phase: str
    deps: tuple[str, ...] = ()
    tool: str = ""
    timeout_seconds: float = 60.0
    retries: int = 1

    def __post_init__(self) -> None:
        self.id = self.id.strip()
        self.phase = self.phase.strip().lower()
        self.tool = self.tool.strip().lower()
        self.deps = tuple(dict.fromkeys(item.strip() for item in self.deps if item.strip()))
        if not self.id:
            raise ValueError("PhaseStep.id cannot be empty.")
        if not self.phase:
            raise ValueError("PhaseStep.phase cannot be empty.")
        if not self.tool:
            raise ValueError("PhaseStep.tool cannot be empty.")
        self.timeout_seconds = float(self.timeout_seconds)
        self.retries = max(0, int(self.retries))
