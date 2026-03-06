"""Low-level content sniffing heuristics for format detection."""

from __future__ import annotations

from nocturna_engine.normalization.detector._types import (
    DetectionResult,
    InputFormat,
    _UTF8_BOM,
    _XML_DECLARATION,
    _XML_DECLARATION_UPPER,
)


def _strip_bom(data: bytes) -> bytes:
    """Strip UTF-8 BOM if present."""
    if data.startswith(_UTF8_BOM):
        return data[len(_UTF8_BOM) :]
    return data


def _sniff_structure(sample: bytes, *, tool_hint: str | None) -> DetectionResult | None:
    """Attempt structural format detection from raw bytes."""
    stripped = sample.lstrip()
    if not stripped:
        return None

    # HTML detection: must come BEFORE XML since HTML also starts with '<'.
    if _looks_like_html(stripped):
        return _classify_html(stripped, tool_hint=tool_hint)

    # XML detection: starts with '<?xml' or '<'.
    if stripped.startswith(_XML_DECLARATION) or stripped.startswith(_XML_DECLARATION_UPPER):
        return _classify_xml(stripped, tool_hint=tool_hint)

    if stripped[:1] == b"<":
        return _classify_xml(stripped, tool_hint=tool_hint)

    # JSONL detection: multiple '{' lines takes priority over single JSON object.
    # Must check before JSON object since JSONL also starts with '{'.
    if stripped[:1] == b"{" and _looks_like_jsonl(stripped):
        return DetectionResult(
            format=InputFormat.JSONL,
            confidence=0.85,
            method="jsonl_multiline_sniff",
            tool_hint=tool_hint,
        )

    # JSON object: starts with '{'.
    if stripped[:1] == b"{":
        return _classify_json_object(stripped, tool_hint=tool_hint)

    # JSON array: starts with '[' followed by JSON-like content.
    if stripped[:1] == b"[" and _looks_like_json_array(stripped):
        return _classify_json_array(stripped, tool_hint=tool_hint)

    # CSV detection: check for comma/tab-separated header-like content.
    if _looks_like_csv(stripped):
        return DetectionResult(
            format=InputFormat.CSV,
            confidence=0.6,
            method="csv_header_sniff",
            tool_hint=tool_hint,
        )

    # JSONL fallback for non-'{'-starting but still multi-JSON-line data.
    if _looks_like_jsonl(stripped):
        return DetectionResult(
            format=InputFormat.JSONL,
            confidence=0.7,
            method="jsonl_multiline_fallback",
            tool_hint=tool_hint,
        )

    return None


def _classify_html(data: bytes, *, tool_hint: str | None) -> DetectionResult:
    """Classify an HTML document for the HTML parser."""
    return DetectionResult(
        format=InputFormat.HTML,
        confidence=0.90,
        method="html_structure_sniff",
        tool_hint=tool_hint,
    )


def _looks_like_html(data: bytes) -> bool:
    """Heuristic: check if data looks like an HTML document rather than XML."""
    lowered = data[:4096].lower()
    # Explicit HTML markers.
    if b"<!doctype html" in lowered:
        return True
    if b"<html" in lowered:
        return True
    # An opening '<' followed by typical HTML-only tags before any XML declaration.
    if data.lstrip().startswith(b"<?xml") or data.lstrip().startswith(b"<?XML"):
        return False
    # Check for HTML body/head tags (not found in XML tool output).
    if b"<head" in lowered or b"<body" in lowered:
        return True
    return False


def _classify_xml(data: bytes, *, tool_hint: str | None) -> DetectionResult:
    """Classify XML content as nmap, nessus, openvas, burp, or generic."""
    lowered = data[:2048].lower()

    # HTML masquerading as XML: if we see <html> or <!doctype html> in XML-like data,
    # route to the HTML parser instead of XML generic.
    if b"<html" in lowered or b"<!doctype html" in lowered:
        return DetectionResult(
            format=InputFormat.HTML,
            confidence=0.85,
            method="html_in_xml_sniff",
            tool_hint=tool_hint,
        )

    # Nmap detection: look for nmaprun element or nmap DTD.
    if b"<nmaprun" in lowered or b"nmap.dtd" in lowered or b"scanner=\"nmap\"" in lowered:
        return DetectionResult(
            format=InputFormat.XML_NMAP,
            confidence=0.95,
            method="xml_nmap_element_sniff",
            tool_hint=tool_hint or "nmap",
        )

    if tool_hint and tool_hint.lower() == "nmap":
        return DetectionResult(
            format=InputFormat.XML_NMAP,
            confidence=0.85,
            method="xml_nmap_tool_hint",
            tool_hint="nmap",
        )

    # Nessus detection: look for NessusClientData root element.
    if b"<nessusclientdata" in lowered:
        return DetectionResult(
            format=InputFormat.XML_GENERIC,
            confidence=0.95,
            method="xml_nessus_element_sniff",
            tool_hint=tool_hint or "nessus",
        )

    # Burp detection: look for <issues> root with Burp-like children.
    if b"<issues" in lowered and b"<issue>" in lowered:
        return DetectionResult(
            format=InputFormat.XML_GENERIC,
            confidence=0.90,
            method="xml_burp_element_sniff",
            tool_hint=tool_hint or "burp",
        )

    # OpenVAS detection: <report> without nmaprun.
    if b"<report" in lowered and b"<nmaprun" not in lowered:
        # Check for OpenVAS-specific markers.
        if b"<results>" in lowered or b"<result>" in lowered or b"format_id" in lowered:
            return DetectionResult(
                format=InputFormat.XML_GENERIC,
                confidence=0.85,
                method="xml_openvas_element_sniff",
                tool_hint=tool_hint or "openvas",
            )

    # JUnit XML detection: <testsuites> or <testsuite> root elements.
    if b"<testsuites" in lowered or b"<testsuite" in lowered:
        return DetectionResult(
            format=InputFormat.XML_JUNIT,
            confidence=0.9,
            method="xml_junit_element_sniff",
            tool_hint=tool_hint,
        )

    return DetectionResult(
        format=InputFormat.XML_GENERIC,
        confidence=0.7,
        method="xml_declaration_sniff",
        tool_hint=tool_hint,
    )


def _classify_json_object(data: bytes, *, tool_hint: str | None) -> DetectionResult:
    """Classify a JSON object as SARIF, tool-specific, or generic."""
    lowered = data[:4096].lower()

    # SARIF detection: look for "$schema" with sarif or "version" + "runs".
    if b"sarif" in lowered and (b'"$schema"' in lowered or b'"runs"' in lowered):
        return DetectionResult(
            format=InputFormat.SARIF,
            confidence=0.95,
            method="sarif_schema_sniff",
            tool_hint=tool_hint,
        )

    if b'"version"' in lowered and b'"runs"' in lowered:
        return DetectionResult(
            format=InputFormat.SARIF,
            confidence=0.8,
            method="sarif_structure_sniff",
            tool_hint=tool_hint,
        )

    return DetectionResult(
        format=InputFormat.JSON,
        confidence=0.8,
        method="json_object_sniff",
        tool_hint=tool_hint,
    )


def _classify_json_array(data: bytes, *, tool_hint: str | None) -> DetectionResult:
    """Classify a JSON array as generic JSON."""
    return DetectionResult(
        format=InputFormat.JSON,
        confidence=0.75,
        method="json_array_sniff",
        tool_hint=tool_hint,
    )


def _looks_like_json_array(data: bytes) -> bool:
    """Heuristic: verify that '[' starts an actual JSON array, not a tag like [CRITICAL]."""
    # Skip whitespace after '['.
    inner = data[1:256].lstrip()
    if not inner:
        return False
    # A JSON array should have elements starting with '{', '"', digit, 'true', 'false', 'null', or '['.
    first_char = inner[:1]
    if first_char in (b'{', b'"', b'[', b't', b'f', b'n'):
        return True
    if first_char and first_char[0:1].isdigit():
        return True
    # If it starts with an uppercase letter (like [CRITICAL]), it's not JSON.
    return False


def _looks_like_csv(data: bytes) -> bool:
    """Heuristic: check if first line looks like CSV headers."""
    first_newline = data.find(b"\n")
    if first_newline == -1:
        first_line = data
    else:
        first_line = data[:first_newline]

    decoded = first_line.decode("utf-8", errors="replace").strip()
    if not decoded:
        return False

    # CSV should have multiple comma-separated fields, none of which start with '{' or '<'.
    if decoded.startswith("{") or decoded.startswith("<") or decoded.startswith("["):
        return False

    commas = decoded.count(",")
    tabs = decoded.count("\t")
    return commas >= 2 or tabs >= 2


def _looks_like_jsonl(data: bytes) -> bool:
    """Heuristic: check if data has multiple newline-separated JSON objects."""
    lines = data.split(b"\n", 5)
    json_lines = 0
    for line in lines[:5]:
        stripped = line.strip()
        if stripped and stripped[:1] == b"{":
            json_lines += 1
    return json_lines >= 2
