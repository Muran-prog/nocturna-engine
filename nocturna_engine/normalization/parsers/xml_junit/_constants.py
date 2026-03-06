"""Regex patterns for extracting structured data from JUnit failure text."""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Regex patterns for extracting structured data from failure text
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_FILE_PATH_RE = re.compile(r"(/[\w./-]+(?::\d+)?)")
_RESOURCE_RE = re.compile(r"Resource:\s*(.+)", re.IGNORECASE)
_SEVERITY_RE = re.compile(
    r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)\b",
    re.IGNORECASE,
)
