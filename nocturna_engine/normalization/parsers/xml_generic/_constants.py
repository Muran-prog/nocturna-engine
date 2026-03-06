"""Constants for the generic XML parser: severity tables, root elements, element names."""

from __future__ import annotations

from nocturna_engine.models.finding import SeverityLevel

# ---------------------------------------------------------------------------
# XML format detection: root element → format identifier
# ---------------------------------------------------------------------------

NESSUS_ROOT = "NessusClientData_v2"
OPENVAS_ROOT = "report"
BURP_ROOT = "issues"

# Lowercase lookup table for root element → internal format tag.
ROOT_ELEMENT_MAP: dict[str, str] = {
    "nessusclientdata_v2": "nessus",
    "nessusclientdata": "nessus",
    "issues": "burp",
    # OpenVAS uses <report> but so do other tools; resolved contextually.
}

# ---------------------------------------------------------------------------
# Nessus severity: numeric string → SeverityLevel (hardcoded, not SeverityMap)
# ---------------------------------------------------------------------------

NESSUS_SEVERITY_MAP: dict[int, SeverityLevel] = {
    0: SeverityLevel.INFO,
    1: SeverityLevel.LOW,
    2: SeverityLevel.MEDIUM,
    3: SeverityLevel.HIGH,
    4: SeverityLevel.CRITICAL,
}

# ---------------------------------------------------------------------------
# Nessus element names expected as children of <ReportItem>
# ---------------------------------------------------------------------------

NESSUS_TEXT_ELEMENTS: frozenset[str] = frozenset({
    "description",
    "solution",
    "synopsis",
    "plugin_output",
    "cvss3_base_score",
    "cvss_base_score",
    "cve",
    "cwe",
    "risk_factor",
    "see_also",
    "plugin_name",
    "fname",
    "plugin_type",
    "script_version",
})

# ---------------------------------------------------------------------------
# OpenVAS element names expected inside <result>
# ---------------------------------------------------------------------------

OPENVAS_TEXT_ELEMENTS: frozenset[str] = frozenset({
    "name",
    "host",
    "port",
    "threat",
    "description",
    "severity",
    "original_threat",
})

OPENVAS_NVT_TEXT_ELEMENTS: frozenset[str] = frozenset({
    "oid",
    "name",
    "cve",
    "cvss_base",
    "type",
    "family",
    "solution",
    "tags",
})

# ---------------------------------------------------------------------------
# Burp element names expected inside <issue>
# ---------------------------------------------------------------------------

BURP_TEXT_ELEMENTS: frozenset[str] = frozenset({
    "serialNumber",
    "type",
    "name",
    "host",
    "path",
    "location",
    "severity",
    "confidence",
    "issueBackground",
    "remediationBackground",
    "issueDetail",
    "remediationDetail",
    "vulnerabilityClassifications",
})

# ---------------------------------------------------------------------------
# Generic fallback: element names that hint at vulnerability data
# ---------------------------------------------------------------------------

GENERIC_VULN_ELEMENT_NAMES: frozenset[str] = frozenset({
    "vulnerability",
    "finding",
    "issue",
    "vuln",
    "alert",
    "defect",
    "risk",
    "threat",
    "weakness",
    "flaw",
    "bug",
})

GENERIC_VULN_CHILD_NAMES: frozenset[str] = frozenset({
    "name",
    "title",
    "summary",
    "description",
    "severity",
    "risk",
    "threat",
    "host",
    "target",
    "ip",
    "url",
    "port",
    "cve",
    "cwe",
    "cvss",
    "solution",
    "remediation",
    "output",
    "detail",
    "evidence",
    "impact",
    "reference",
})
