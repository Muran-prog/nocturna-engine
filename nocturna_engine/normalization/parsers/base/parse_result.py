"""Parsing result container."""

from __future__ import annotations

from dataclasses import dataclass, field

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.metadata import NormalizationStats
from nocturna_engine.normalization.parsers.base.parse_issue import ParseIssue


@dataclass(slots=True)
class ParseResult:
    """Result of parsing one chunk or complete input.

    .. warning:: Ownership contract

       ``ParseResult`` is a **mutable** container. Ownership transfers to the
       caller upon return from ``parse()`` / ``parse_stream()``. Parsers
       **must not** retain a reference to a yielded ``ParseResult`` or its
       ``findings`` / ``issues`` lists after returning.

    Attributes:
        findings: Successfully parsed and validated Finding objects.
        issues: Non-fatal issues encountered during parsing.
        stats: Aggregate parsing statistics.
    """

    findings: list[Finding] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)
    stats: NormalizationStats = field(default_factory=NormalizationStats)
