"""Abstract interface for post-scan analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class BaseAnalyzer(ABC):
    """Base class for result analyzers.

    Analyzers can enrich, deduplicate, or correlate raw tool findings before
    reporting.
    """

    name: ClassVar[str] = "base-analyzer"

    @abstractmethod
    async def analyze(self, scan_results: list[ScanResult], request: ScanRequest) -> list[Finding]:
        """Produce normalized findings from scan results.

        Args:
            scan_results: Results produced by tool plugins.
            request: Original scan request.

        Returns:
            list[Finding]: Enriched findings list.
        """

