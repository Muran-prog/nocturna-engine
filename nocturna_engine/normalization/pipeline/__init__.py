"""Normalization pipeline: detect format, parse, validate, deduplicate."""

from nocturna_engine.normalization.pipeline.config import NormalizationConfig
from nocturna_engine.normalization.pipeline.dedup import deduplicate_findings
from nocturna_engine.normalization.pipeline.result import NormalizationResult
from nocturna_engine.normalization.pipeline.runner import NormalizationPipeline

__all__ = [
    "NormalizationConfig",
    "NormalizationPipeline",
    "NormalizationResult",
    "deduplicate_findings",
]
