"""Normalization pipeline runner package.

Re-exports ``NormalizationPipeline`` so that existing imports like
``from nocturna_engine.normalization.pipeline.runner import NormalizationPipeline``
continue to work without changes.
"""

from nocturna_engine.normalization.pipeline.runner._pipeline import NormalizationPipeline

__all__ = ["NormalizationPipeline"]
