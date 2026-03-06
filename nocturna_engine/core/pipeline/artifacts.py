"""Artifact store for cross-phase DAG orchestration."""

from __future__ import annotations

from typing import Any


class ArtifactStore:
    """Namespaced artifact storage shared through pipeline context."""

    def __init__(self) -> None:
        self._items: dict[str, Any] = {}

    @staticmethod
    def build_key(phase: str, tool: str, key: str) -> str:
        """Build namespaced key in ``phase.tool.key`` form."""

        parts = (phase.strip().lower(), tool.strip().lower(), key.strip().lower())
        if any(not part for part in parts):
            raise ValueError("Artifact key must include non-empty phase, tool, and key.")
        return ".".join(parts)

    def put(self, phase: str, tool: str, key: str, value: Any) -> str:
        """Store one artifact value and return its namespaced key."""

        namespaced_key = self.build_key(phase, tool, key)
        self._items[namespaced_key] = value
        return namespaced_key

    def get(self, namespaced_key: str, default: Any = None) -> Any:
        """Read one artifact by namespaced key."""

        return self._items.get(namespaced_key.strip().lower(), default)

    def list(self, prefix: str | None = None) -> list[str]:
        """List stored artifact keys, optionally filtered by prefix."""

        if prefix is None:
            return sorted(self._items.keys())
        normalized_prefix = prefix.strip().lower()
        return sorted(key for key in self._items if key.startswith(normalized_prefix))
