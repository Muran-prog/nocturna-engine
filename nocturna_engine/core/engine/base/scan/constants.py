"""Phase constants used by scan orchestration mixins."""

from __future__ import annotations

_PHASE_SEQUENCE: tuple[str, ...] = ("recon", "enrich", "validate", "exploit")
_PHASE_ALIASES: dict[str, set[str]] = {
    "recon": {
        "recon",
        "discovery",
        "enumeration",
        "intel",
        "osint",
        "collect",
        "gather",
        "dns",
        "subdomain",
    },
    "enrich": {
        "enrich",
        "enrichment",
        "context",
        "correlate",
        "fingerprint",
        "profiling",
    },
    "validate": {
        "validate",
        "validation",
        "scan",
        "scanning",
        "analyze",
        "analysis",
        "audit",
        "testing",
        "vulnerability",
        "sast",
        "dast",
    },
    "exploit": {
        "exploit",
        "exploitation",
        "attack",
        "offensive",
        "fuzz",
        "fuzzing",
        "bruteforce",
    },
}

