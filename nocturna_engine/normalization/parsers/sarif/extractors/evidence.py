"""SARIF evidence building — fingerprints, related locations, code flows, fixes."""

from __future__ import annotations

from typing import Any


def build_sarif_evidence(
    result: dict[str, Any],
    *,
    rule_id: str,
) -> dict[str, Any]:
    """Build evidence dict from SARIF result data.

    Extracts location, fingerprints, partialFingerprints, related
    locations, code flow summary, and fix information.
    """
    evidence: dict[str, Any] = {}
    if rule_id:
        evidence["rule_id"] = rule_id

    # Location details.
    locations = result.get("locations")
    if isinstance(locations, list) and locations:
        loc = locations[0]
        if isinstance(loc, dict):
            physical = loc.get("physicalLocation")
            if isinstance(physical, dict):
                region = physical.get("region")
                if isinstance(region, dict):
                    evidence["location"] = {
                        k: region[k]
                        for k in ("startLine", "startColumn", "endLine", "endColumn")
                        if k in region
                    }

    # Fingerprints.
    fingerprints = result.get("fingerprints")
    if isinstance(fingerprints, dict) and fingerprints:
        evidence["sarif_fingerprints"] = fingerprints

    # Partial fingerprints.
    partial_fingerprints = result.get("partialFingerprints")
    if isinstance(partial_fingerprints, dict) and partial_fingerprints:
        evidence["sarif_partial_fingerprints"] = partial_fingerprints

    # Related locations.
    evidence.update(_extract_related_locations(result))

    # Code flows.
    evidence.update(_extract_code_flows(result))

    # Fix information.
    evidence.update(_extract_fix_info(result))

    return evidence


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_related_locations(result: dict[str, Any]) -> dict[str, Any]:
    """Extract ``relatedLocations`` into a flat evidence sub-dict."""
    raw = result.get("relatedLocations")
    if not isinstance(raw, list) or not raw:
        return {}

    related: list[dict[str, Any]] = []
    for loc in raw:
        if not isinstance(loc, dict):
            continue
        physical = loc.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict):
            continue
        uri = str(artifact.get("uri", "")).strip()
        if not uri:
            continue
        entry: dict[str, Any] = {"uri": uri}
        region = physical.get("region")
        if isinstance(region, dict):
            if "startLine" in region:
                entry["startLine"] = region["startLine"]
            if "endLine" in region:
                entry["endLine"] = region["endLine"]
        related.append(entry)

    if related:
        return {"related_locations": related}
    return {}


def _extract_code_flows(result: dict[str, Any]) -> dict[str, Any]:
    """Extract code-flow summary from ``codeFlows[].threadFlows[].locations[]``.

    Returns ``code_flow_length`` (total steps across first thread flow)
    and ``code_flow_summary`` ("first_location → last_location").
    """
    code_flows = result.get("codeFlows")
    if not isinstance(code_flows, list) or not code_flows:
        return {}

    # Use the first codeFlow / first threadFlow.
    first_flow = code_flows[0]
    if not isinstance(first_flow, dict):
        return {}

    thread_flows = first_flow.get("threadFlows")
    if not isinstance(thread_flows, list) or not thread_flows:
        return {}

    first_thread = thread_flows[0]
    if not isinstance(first_thread, dict):
        return {}

    tfl_locations = first_thread.get("locations")
    if not isinstance(tfl_locations, list) or not tfl_locations:
        return {}

    flow_length = len(tfl_locations)
    evidence: dict[str, Any] = {"code_flow_length": flow_length}

    first_uri = _uri_from_thread_flow_location(tfl_locations[0])
    last_uri = _uri_from_thread_flow_location(tfl_locations[-1])
    if first_uri and last_uri:
        evidence["code_flow_summary"] = f"{first_uri} → {last_uri}"

    return evidence


def _uri_from_thread_flow_location(tfl: Any) -> str:
    """Extract artifact URI from a single threadFlowLocation entry."""
    if not isinstance(tfl, dict):
        return ""
    location = tfl.get("location")
    if not isinstance(location, dict):
        return ""
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return ""
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        return ""
    return str(artifact.get("uri", "")).strip()


def _extract_fix_info(result: dict[str, Any]) -> dict[str, Any]:
    """Extract fix suggestion metadata from ``fixes[]``."""
    fixes = result.get("fixes")
    if not isinstance(fixes, list) or not fixes:
        return {}

    evidence: dict[str, Any] = {"has_fix": True}
    first_fix = fixes[0]
    if isinstance(first_fix, dict):
        desc = first_fix.get("description")
        if isinstance(desc, dict):
            text = str(desc.get("text", "")).strip()
            if text:
                evidence["fix_description"] = text

    return evidence
