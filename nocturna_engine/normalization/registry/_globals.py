"""Global singleton registry instance and decorator-based registration."""

from __future__ import annotations

from typing import Any

from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.registry._registry import ParserRegistry

# Global singleton registry instance.
_global_registry = ParserRegistry()


def get_global_registry() -> ParserRegistry:
    """Return the global parser registry singleton.

    Returns:
        ParserRegistry: Global registry instance.
    """
    return _global_registry


def register_parser(
    *,
    name: str,
    formats: list[InputFormat],
    tool_patterns: list[str] | None = None,
    priority: int = 0,
) -> Any:
    """Decorator to register a parser class in the global registry.

    Args:
        name: Unique parser name.
        formats: Input formats this parser handles.
        tool_patterns: Optional tool name patterns for disambiguation.
        priority: Higher priority parsers are tried first.

    Returns:
        Decorator function.
    """

    def _decorator(parser_class: type[Any]) -> type[Any]:
        _global_registry.register(
            parser_class,
            name=name,
            formats=formats,
            tool_patterns=tool_patterns,
            priority=priority,
        )
        return parser_class

    return _decorator
