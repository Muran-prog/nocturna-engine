"""Generic JSON parser with tool-specific field mapping heuristics."""

from nocturna_engine.normalization.parsers.json_generic.field_mapping import (
    _TOOL_FIELD_MAPS,
    _deep_get,
    _detect_tool_shape,
    _first_non_empty,
)
from nocturna_engine.normalization.parsers.json_generic.parser import GenericJsonParser

__all__ = [
    "GenericJsonParser",
    "_TOOL_FIELD_MAPS",
    "_deep_get",
    "_detect_tool_shape",
    "_first_non_empty",
]
