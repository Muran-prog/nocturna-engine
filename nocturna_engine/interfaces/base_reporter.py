"""Abstract interface for report generators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


class BaseReporter(ABC):
    """Base class for report output components."""

    name: ClassVar[str] = "base-reporter"

    @abstractmethod
    async def generate_report(
        self,
        request: ScanRequest,
        scan_results: list[ScanResult],
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Generate a report payload.

        Args:
            request: Original scan request.
            scan_results: Tool results.
            findings: Final findings.

        Returns:
            dict[str, Any]: Report payload ready for persistence or transport.
        """

