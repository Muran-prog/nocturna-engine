"""Format hint resolution: user-provided string → InputFormat."""

from __future__ import annotations

from nocturna_engine.normalization.detector._types import InputFormat


def _resolve_hint(hint: str) -> InputFormat | None:
    """Resolve a user-provided format hint string to an InputFormat."""
    normalized = hint.strip().lower().replace("-", "_").replace(" ", "_")
    _HINT_ALIASES: dict[str, InputFormat] = {
        "sarif": InputFormat.SARIF,
        "sarif2": InputFormat.SARIF,
        "sarif_v2": InputFormat.SARIF,
        "json": InputFormat.JSON,
        "jsonl": InputFormat.JSONL,
        "ndjson": InputFormat.JSONL,
        "jsonlines": InputFormat.JSONL,
        "xml": InputFormat.XML_GENERIC,
        "xml_nmap": InputFormat.XML_NMAP,
        "nmap": InputFormat.XML_NMAP,
        "nmap_xml": InputFormat.XML_NMAP,
        "xml_junit": InputFormat.XML_JUNIT,
        "junit": InputFormat.XML_JUNIT,
        "junit_xml": InputFormat.XML_JUNIT,
        "xunit": InputFormat.XML_JUNIT,
        "csv": InputFormat.CSV,
        "tsv": InputFormat.CSV,
        "plaintext": InputFormat.PLAINTEXT,
        "text": InputFormat.PLAINTEXT,
        "txt": InputFormat.PLAINTEXT,
        "nessus": InputFormat.XML_GENERIC,
        "nessus_xml": InputFormat.XML_GENERIC,
        "openvas": InputFormat.XML_GENERIC,
        "openvas_xml": InputFormat.XML_GENERIC,
        "burp": InputFormat.XML_GENERIC,
        "burp_xml": InputFormat.XML_GENERIC,
        "burpsuite": InputFormat.XML_GENERIC,
        "qualys": InputFormat.XML_GENERIC,
        "qualys_xml": InputFormat.XML_GENERIC,
        "nikto": InputFormat.XML_GENERIC,
        "nikto_xml": InputFormat.XML_GENERIC,
        "xml_generic": InputFormat.XML_GENERIC,
        "html": InputFormat.HTML,
        "html_report": InputFormat.HTML,
        "nikto_html": InputFormat.HTML,
        "zap_html": InputFormat.HTML,
        "burp_html": InputFormat.HTML,
    }
    return _HINT_ALIASES.get(normalized)
