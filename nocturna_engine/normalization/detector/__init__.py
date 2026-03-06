"""Input format detection via content sniffing, magic bytes, and explicit hints."""

from nocturna_engine.normalization.detector._api import detect_format
from nocturna_engine.normalization.detector._hints import _resolve_hint
from nocturna_engine.normalization.detector._sniffers import (
    _classify_html,
    _classify_json_array,
    _classify_json_object,
    _classify_xml,
    _looks_like_csv,
    _looks_like_html,
    _looks_like_json_array,
    _looks_like_jsonl,
    _sniff_structure,
    _strip_bom,
)
from nocturna_engine.normalization.detector._types import (
    DetectionResult,
    InputFormat,
    _SNIFF_SIZE,
    _UTF8_BOM,
    _XML_DECLARATION,
    _XML_DECLARATION_UPPER,
)

__all__ = [
    # Public API
    "detect_format",
    "DetectionResult",
    "InputFormat",
    # Constants (used by tests)
    "_SNIFF_SIZE",
    "_UTF8_BOM",
    "_XML_DECLARATION",
    "_XML_DECLARATION_UPPER",
    # Internal helpers (re-exported for backward compatibility / tests)
    "_resolve_hint",
    "_strip_bom",
    "_sniff_structure",
    "_classify_xml",
    "_classify_html",
    "_looks_like_html",
    "_classify_json_object",
    "_classify_json_array",
    "_looks_like_json_array",
    "_looks_like_csv",
    "_looks_like_jsonl",
]
