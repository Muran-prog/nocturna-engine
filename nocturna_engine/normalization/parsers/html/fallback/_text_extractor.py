"""Fallback text extractor for HTML documents without recognizable tables.

Scans raw text content for CVE patterns and creates minimal findings,
following the same approach as the plaintext parser's CVE extraction.
"""

from __future__ import annotations

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.parsers.html._constants import _CVE_PATTERN


def extract_cve_findings(
    text_chunks: list[str],
    *,
    tool_name: str,
    target_hint: str,
) -> list[Finding]:
    """Extract CVE-based findings from raw text chunks.

    Scans each text chunk for CVE identifiers and produces one finding
    per unique CVE. Duplicates within the same document are suppressed.

    Args:
        text_chunks: List of text fragments extracted from HTML.
        tool_name: Tool name for the finding.
        target_hint: Default target if none can be determined.

    Returns:
        list[Finding]: Deduplicated CVE findings.
    """
    seen_cves: set[str] = set()
    findings: list[Finding] = []

    for chunk in text_chunks:
        for match in _CVE_PATTERN.finditer(chunk):
            cve_id = match.group(0).upper()
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            # Extract surrounding context for the description.
            start = max(0, match.start() - 80)
            end = min(len(chunk), match.end() + 120)
            context = chunk[start:end].strip()

            finding = Finding(
                title=cve_id,
                description=f"CVE reference found in HTML report: {context}",
                severity=SeverityLevel.HIGH,
                tool=tool_name,
                target=target_hint,
                cwe=None,
                evidence={
                    "cve": cve_id,
                    "extraction_method": "html_text_fallback",
                },
            )
            findings.append(finding)

    return findings
