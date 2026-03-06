"""Extraction patterns for the plaintext parser."""

from __future__ import annotations

import re
from dataclasses import dataclass

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers._shared.patterns import CVE_PATTERN


@dataclass(slots=True, frozen=True)
class ExtractionPattern:
    """A regex pattern for extracting findings from plaintext output.

    Attributes:
        name: Human-readable pattern name.
        pattern: Compiled regex with named groups.
        severity: Default severity for matches from this pattern.
        title_template: Template for finding title using regex group names.
        description_template: Template for finding description using regex group names.
    """

    name: str
    pattern: re.Pattern[str]
    severity: SeverityLevel
    title_template: str
    description_template: str


# Built-in extraction patterns for common security tool plaintext output.
_BUILTIN_PATTERNS: list[ExtractionPattern] = [
    # CVE reference pattern: "CVE-YYYY-NNNNN" with optional context.
    ExtractionPattern(
        name="cve_reference",
        pattern=re.compile(
            rf"(?P<cve>{CVE_PATTERN.pattern})\s*[-:]\s*(?P<description>.+)",
            re.IGNORECASE,
        ),
        severity=SeverityLevel.HIGH,
        title_template="{cve}",
        description_template="{description}",
    ),
    # IP:port open pattern (common in masscan, zmap output).
    ExtractionPattern(
        name="ip_port_open",
        pattern=re.compile(
            r"(?:Discovered\s+)?(?:open\s+)?(?:port\s+)?(?P<port>\d{1,5})/(?P<proto>tcp|udp)"
            r"\s+on\s+(?P<host>[\d.]+|[\da-fA-F:]+)",
            re.IGNORECASE,
        ),
        severity=SeverityLevel.LOW,
        title_template="Open port {port}/{proto} on {host}",
        description_template="Port {port}/{proto} is open on {host}.",
    ),
    # Generic vulnerability line: "[SEVERITY] title/description".
    ExtractionPattern(
        name="severity_prefix",
        pattern=re.compile(
            r"\[(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO|WARNING|ERROR)\]\s+(?P<title>.+)",
            re.IGNORECASE,
        ),
        severity=SeverityLevel.INFO,  # Overridden by captured severity.
        title_template="{title}",
        description_template="{title}",
    ),
    # URL with status code (common in web scanners).
    ExtractionPattern(
        name="url_status",
        pattern=re.compile(
            r"(?P<url>https?://\S+)\s+\[(?P<status>\d{3})\](?:\s+(?P<info>.+))?",
            re.IGNORECASE,
        ),
        severity=SeverityLevel.INFO,
        title_template="HTTP {status} at {url}",
        description_template="HTTP {status} response at {url}. {info}",
    ),
]
