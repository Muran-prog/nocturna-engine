"""Finding deduplication and merging helpers."""

from __future__ import annotations

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.severity import merge_severities


def deduplicate_findings(
    findings: list[Finding],
) -> tuple[list[Finding], int]:
    """Deduplicate findings by fingerprint, merging metadata.

    When duplicates are found:
    - Highest severity wins
    - Metadata is merged (found_by_tools list, detection_count)
    - First finding's base data is preserved

    Args:
        findings: List of findings to deduplicate.

    Returns:
        tuple[list[Finding], int]: Deduplicated findings and count of merges.
    """
    fingerprint_groups: dict[str, list[Finding]] = {}
    for finding in findings:
        group = fingerprint_groups.setdefault(finding.fingerprint, [])
        group.append(finding)

    deduplicated: list[Finding] = []
    merge_count = 0

    for fingerprint, group in fingerprint_groups.items():
        if len(group) == 1:
            deduplicated.append(group[0])
            continue

        merge_count += len(group) - 1
        merged = _merge_finding_group(group)
        deduplicated.append(merged)

    return deduplicated, merge_count


def _merge_finding_group(group: list[Finding]) -> Finding:
    """Merge a group of findings with the same fingerprint.

    Args:
        group: Findings sharing the same fingerprint (at least 2).

    Returns:
        Finding: Merged finding with combined metadata.
    """
    # Use highest severity.
    best_severity = merge_severities([f.severity for f in group])

    # Collect tool names.
    tools = list(dict.fromkeys(f.tool for f in group))

    # Merge metadata.
    base = group[0]
    merged_metadata = dict(base.metadata)
    merged_metadata["found_by_tools"] = tools
    merged_metadata["detection_count"] = len(group)

    # Use highest CVSS if available.
    cvss_values = [f.cvss for f in group if f.cvss is not None]
    best_cvss = max(cvss_values) if cvss_values else base.cvss

    # Merge evidence.
    merged_evidence = dict(base.evidence)
    for finding in group[1:]:
        for key, value in finding.evidence.items():
            if key not in merged_evidence:
                merged_evidence[key] = value

    return base.model_copy(update={
        "severity": best_severity,
        "metadata": merged_metadata,
        "cvss": best_cvss,
        "evidence": merged_evidence,
    })
