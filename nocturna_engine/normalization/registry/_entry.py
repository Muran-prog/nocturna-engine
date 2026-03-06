"""Internal registry entry data structure."""

from __future__ import annotations

from typing import Any


class _RegistryEntry:
    """Internal registry entry for one parser."""

    __slots__ = ("name", "parser_class", "tool_patterns", "priority", "formats")

    def __init__(
        self,
        *,
        name: str,
        parser_class: type[Any],
        tool_patterns: list[str],
        priority: int,
        formats: frozenset[Any] | None = None,
    ) -> None:
        self.name = name
        self.parser_class = parser_class
        self.tool_patterns = tool_patterns
        self.priority = priority
        self.formats = formats or frozenset()
