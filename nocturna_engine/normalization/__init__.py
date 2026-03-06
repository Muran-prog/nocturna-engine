"""Universal Finding Normalization (UFN) subsystem for Nocturna Engine.

Accepts raw output from any security tool in any format and normalizes it
into the engine's unified Finding model with fingerprinting, severity mapping,
deduplication, and raw data preservation.

Usage::

    from nocturna_engine.normalization import NormalizationPipeline, NormalizationConfig

    pipeline = NormalizationPipeline()
    result = await pipeline.normalize(
        raw_data,
        config=NormalizationConfig(tool_name="nuclei"),
    )
    for finding in result.findings:
        print(finding.title, finding.severity)
"""

from nocturna_engine.normalization.detector import DetectionResult, InputFormat, detect_format
from nocturna_engine.normalization.errors import (
    FormatDetectionError,
    NormalizationError,
    ParseError,
    ParserNotFoundError,
    ParserRegistrationError,
    SeverityMappingError,
    StreamExhaustedError,
)
from nocturna_engine.normalization.metadata import NormalizationOrigin, NormalizationStats
from nocturna_engine.normalization.pipeline import NormalizationConfig, NormalizationPipeline, NormalizationResult
from nocturna_engine.normalization.registry import ParserRegistry, get_global_registry, register_parser
from nocturna_engine.normalization.severity import SeverityMap, build_severity_map, merge_severities

# Import parsers to trigger decorator-based registration.
import nocturna_engine.normalization.parsers as _parsers  # noqa: F401

__all__ = [
    # Pipeline
    "NormalizationConfig",
    "NormalizationPipeline",
    "NormalizationResult",
    # Detection
    "DetectionResult",
    "InputFormat",
    "detect_format",
    # Registry
    "ParserRegistry",
    "get_global_registry",
    "register_parser",
    # Severity
    "SeverityMap",
    "build_severity_map",
    "merge_severities",
    # Metadata
    "NormalizationOrigin",
    "NormalizationStats",
    # Errors
    "FormatDetectionError",
    "NormalizationError",
    "ParseError",
    "ParserNotFoundError",
    "ParserRegistrationError",
    "SeverityMappingError",
    "StreamExhaustedError",
]
