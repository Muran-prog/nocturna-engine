"""Parser registry with decorator-based registration and format-aware lookup."""

from nocturna_engine.normalization.registry._globals import (
    _global_registry,
    get_global_registry,
    register_parser,
)
from nocturna_engine.normalization.registry._registry import ParserRegistry

__all__ = [
    "ParserRegistry",
    "_global_registry",
    "get_global_registry",
    "register_parser",
]
