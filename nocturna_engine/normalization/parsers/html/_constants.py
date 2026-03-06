"""Constants for the HTML security report parser."""

from __future__ import annotations

from nocturna_engine.normalization.parsers._shared.patterns import (
    CVE_PATTERN as _CVE_PATTERN,
)

# Tags that indicate a security-tool HTML report header row.
_SECURITY_HEADER_KEYWORDS: frozenset[str] = frozenset({
    "vulnerability",
    "finding",
    "severity",
    "risk",
    "host",
    "target",
    "url",
    "uri",
    "description",
    "name",
    "cwe",
    "cvss",
    "confidence",
    "solution",
    "reference",
    "method",
    "alert",
    "issue",
    "plugin",
    "port",
    "protocol",
    "impact",
    "score",
    "detail",
    "summary",
})

# Minimum number of security-related header keywords in a table row
# to treat it as a finding table.
_MIN_SECURITY_HEADERS: int = 2

# Maximum bytes to accumulate in parse_stream before raising.
_MAX_STREAM_BYTES: int = 256 * 1024 * 1024  # 256 MB

# Maximum number of tables to extract from a single document.
_MAX_TABLES: int = 500

# Maximum number of rows per table before stopping.
_MAX_ROWS_PER_TABLE: int = 100_000
