"""Tests for SARIF v2 parser features: extension rules, security-severity,
related locations, code flows, partial fingerprints, fix info, and suppression handling."""

from __future__ import annotations

import json

import pytest

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers.base import ParserConfig
from nocturna_engine.normalization.parsers.sarif import SarifParser
from nocturna_engine.normalization.parsers.sarif.extractors import (
    build_rule_index,
    build_sarif_evidence,
    is_suppressed,
    resolve_severity,
)
from nocturna_engine.normalization.severity import build_severity_map


# ---------------------------------------------------------------------------
# Helpers (same pattern as test_parser_sarif_basic)
# ---------------------------------------------------------------------------


def _cfg(**overrides) -> ParserConfig:
    defaults = dict(
        tool_name="test_tool",
        target_hint="example.com",
        severity_map=build_severity_map(),
        preserve_raw=True,
    )
    defaults.update(overrides)
    return ParserConfig(**defaults)


def _minimal_sarif(
    *,
    version: str = "2.1.0",
    runs: list | None = None,
    results: list | None = None,
    tool_name: str = "test-tool",
    driver_rules: list | None = None,
    extensions: list | None = None,
) -> str:
    """Build a minimal valid SARIF document with optional extensions."""
    if results is None:
        results = [
            {
                "ruleId": "TEST001",
                "level": "warning",
                "message": {"text": "Test finding message"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/main.py"},
                            "region": {"startLine": 10, "startColumn": 1},
                        }
                    }
                ],
            }
        ]
    if runs is None:
        driver: dict = {"name": tool_name, "rules": driver_rules or []}
        tool: dict = {"driver": driver}
        if extensions is not None:
            tool["extensions"] = extensions
        runs = [{"tool": tool, "results": results}]
    doc = {"version": version, "$schema": "https://sarif.schema", "runs": runs}
    return json.dumps(doc)


def _make_run(
    *,
    driver_rules: list | None = None,
    extensions: list | None = None,
    results: list | None = None,
    tool_name: str = "test-tool",
) -> dict:
    """Build an in-memory SARIF run dict for unit-testing extractors."""
    driver: dict = {"name": tool_name, "rules": driver_rules or []}
    tool: dict = {"driver": driver}
    if extensions is not None:
        tool["extensions"] = extensions
    run: dict = {"tool": tool, "results": results or []}
    return run


# ---------------------------------------------------------------------------
# Feature 1: Extension Rules (build_rule_index)
# ---------------------------------------------------------------------------


class TestExtensionRules:
    """build_rule_index should index tool.extensions[].rules."""

    def test_extension_rules_are_indexed(self) -> None:
        run = _make_run(
            extensions=[
                {
                    "name": "codeql-pack",
                    "rules": [
                        {"id": "EXT001", "shortDescription": {"text": "Ext rule"}},
                    ],
                }
            ],
        )
        index = build_rule_index(run)
        assert "EXT001" in index
        assert index["EXT001"]["shortDescription"]["text"] == "Ext rule"

    def test_driver_rules_override_extension_rules_on_collision(self) -> None:
        run = _make_run(
            driver_rules=[
                {"id": "SHARED", "shortDescription": {"text": "Driver version"}},
            ],
            extensions=[
                {
                    "name": "ext",
                    "rules": [
                        {"id": "SHARED", "shortDescription": {"text": "Extension version"}},
                    ],
                }
            ],
        )
        index = build_rule_index(run)
        assert index["SHARED"]["shortDescription"]["text"] == "Driver version"

    def test_multiple_extensions(self) -> None:
        run = _make_run(
            extensions=[
                {"name": "ext-a", "rules": [{"id": "A001"}]},
                {"name": "ext-b", "rules": [{"id": "B001"}]},
            ],
        )
        index = build_rule_index(run)
        assert "A001" in index
        assert "B001" in index

    def test_malformed_extensions_not_list(self) -> None:
        run = _make_run()
        run["tool"]["extensions"] = "not-a-list"
        index = build_rule_index(run)
        # Extensions ignored; only driver rules remain (empty).
        assert index == {}

    def test_malformed_extensions_missing_rules_key(self) -> None:
        run = _make_run(extensions=[{"name": "no-rules-key"}])
        index = build_rule_index(run)
        assert index == {}

    def test_malformed_extensions_rules_not_list(self) -> None:
        run = _make_run(extensions=[{"name": "bad", "rules": "not-a-list"}])
        index = build_rule_index(run)
        assert index == {}

    async def test_parser_uses_extension_rules_for_enrichment(self) -> None:
        """Integration: extension rule CWE/severity enrichment flows through parser."""
        ext_rules = [
            {
                "id": "EXT-SEC-01",
                "shortDescription": {"text": "SQL injection"},
                "properties": {
                    "cwe": "CWE-89",
                    "security-severity": "9.5",
                },
            }
        ]
        results = [
            {
                "ruleId": "EXT-SEC-01",
                "level": "note",
                "message": {"text": "Possible SQL injection found"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app/db.py"},
                            "region": {"startLine": 42},
                        }
                    }
                ],
            }
        ]
        sarif = _minimal_sarif(
            extensions=[{"name": "security-pack", "rules": ext_rules}],
            results=results,
        )
        parser = SarifParser(_cfg())
        result = await parser.parse(sarif)
        assert len(result.findings) == 1
        f = result.findings[0]
        # security-severity 9.5 -> CRITICAL (overrides level="note")
        assert f.severity == SeverityLevel.CRITICAL
        assert f.cwe == "CWE-89"


# ---------------------------------------------------------------------------
# Feature 2: Security-severity (resolve_severity)
# ---------------------------------------------------------------------------


class TestSecuritySeverity:
    """resolve_severity should honour security-severity CVSS score from rule properties."""

    def _resolve(self, *, result: dict | None = None, rule_meta: dict | None = None) -> SeverityLevel:
        return resolve_severity(
            result or {"level": "warning"},
            rule_meta or {},
            config=_cfg(),
            tool_name="test",
        )

    def test_security_severity_9_0_maps_to_critical(self) -> None:
        rule = {"properties": {"security-severity": "9.0"}}
        assert self._resolve(rule_meta=rule) == SeverityLevel.CRITICAL

    def test_security_severity_7_5_maps_to_high(self) -> None:
        rule = {"properties": {"security-severity": "7.5"}}
        assert self._resolve(rule_meta=rule) == SeverityLevel.HIGH

    def test_security_severity_4_0_maps_to_medium(self) -> None:
        rule = {"properties": {"security-severity": "4.0"}}
        assert self._resolve(rule_meta=rule) == SeverityLevel.MEDIUM

    def test_security_severity_2_0_maps_to_low(self) -> None:
        rule = {"properties": {"security-severity": "2.0"}}
        assert self._resolve(rule_meta=rule) == SeverityLevel.LOW

    def test_security_severity_0_0_maps_to_info(self) -> None:
        rule = {"properties": {"security-severity": "0.0"}}
        assert self._resolve(rule_meta=rule) == SeverityLevel.INFO

    def test_security_severity_overrides_level(self) -> None:
        """level=note would be LOW, but security-severity=9.0 -> CRITICAL."""
        result = {"level": "note"}
        rule = {"properties": {"security-severity": "9.0"}}
        assert self._resolve(result=result, rule_meta=rule) == SeverityLevel.CRITICAL

    def test_missing_security_severity_falls_back_to_level(self) -> None:
        result = {"level": "error"}
        rule = {"properties": {}}
        assert self._resolve(result=result, rule_meta=rule) == SeverityLevel.HIGH

    def test_non_numeric_security_severity_ignored(self) -> None:
        result = {"level": "warning"}
        rule = {"properties": {"security-severity": "not-a-number"}}
        # Falls back to level mapping: warning -> medium
        assert self._resolve(result=result, rule_meta=rule) == SeverityLevel.MEDIUM

    def test_out_of_range_security_severity_ignored(self) -> None:
        result = {"level": "warning"}
        rule = {"properties": {"security-severity": "11.0"}}
        # Out of range (>10), ignored; falls back to level mapping: warning -> medium
        assert self._resolve(result=result, rule_meta=rule) == SeverityLevel.MEDIUM


# ---------------------------------------------------------------------------
# Feature 3: Related Locations (build_sarif_evidence)
# ---------------------------------------------------------------------------


class TestRelatedLocations:
    """build_sarif_evidence should extract relatedLocations."""

    def test_related_locations_extracted(self) -> None:
        result = {
            "ruleId": "R1",
            "relatedLocations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "helper.py"},
                        "region": {"startLine": 5, "endLine": 10},
                    }
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "utils.py"},
                        "region": {"startLine": 20},
                    }
                },
            ],
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "related_locations" in evidence
        related = evidence["related_locations"]
        assert len(related) == 2
        assert related[0]["uri"] == "helper.py"
        assert related[0]["startLine"] == 5
        assert related[0]["endLine"] == 10
        assert related[1]["uri"] == "utils.py"
        assert related[1]["startLine"] == 20
        assert "endLine" not in related[1]

    def test_empty_related_locations_produces_no_key(self) -> None:
        result = {"ruleId": "R1", "relatedLocations": []}
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "related_locations" not in evidence

    def test_malformed_related_locations_skipped(self) -> None:
        result = {
            "ruleId": "R1",
            "relatedLocations": [
                "not-a-dict",
                {"physicalLocation": "not-a-dict"},
                {"physicalLocation": {"artifactLocation": "not-a-dict"}},
                {"physicalLocation": {"artifactLocation": {"uri": ""}}},
                # One valid entry to confirm filtering works
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "valid.py"},
                        "region": {"startLine": 1},
                    }
                },
            ],
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "related_locations" in evidence
        assert len(evidence["related_locations"]) == 1
        assert evidence["related_locations"][0]["uri"] == "valid.py"

    def test_no_related_locations_key(self) -> None:
        result = {"ruleId": "R1"}
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "related_locations" not in evidence


# ---------------------------------------------------------------------------
# Feature 4: Code Flows (build_sarif_evidence)
# ---------------------------------------------------------------------------


class TestCodeFlows:
    """build_sarif_evidence should extract code flow summary and length."""

    def test_code_flows_extracted(self) -> None:
        result = {
            "ruleId": "R1",
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {"location": {"physicalLocation": {"artifactLocation": {"uri": "source.py"}}}},
                                {"location": {"physicalLocation": {"artifactLocation": {"uri": "middle.py"}}}},
                                {"location": {"physicalLocation": {"artifactLocation": {"uri": "sink.py"}}}},
                            ]
                        }
                    ]
                }
            ],
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert evidence["code_flow_length"] == 3
        assert evidence["code_flow_summary"] == "source.py \u2192 sink.py"

    def test_empty_code_flows_produces_no_keys(self) -> None:
        result = {"ruleId": "R1", "codeFlows": []}
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "code_flow_length" not in evidence
        assert "code_flow_summary" not in evidence

    def test_single_step_flow(self) -> None:
        result = {
            "ruleId": "R1",
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {"location": {"physicalLocation": {"artifactLocation": {"uri": "only.py"}}}},
                            ]
                        }
                    ]
                }
            ],
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert evidence["code_flow_length"] == 1
        # source == sink for single step
        assert evidence["code_flow_summary"] == "only.py \u2192 only.py"

    def test_no_code_flows_key(self) -> None:
        result = {"ruleId": "R1"}
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "code_flow_length" not in evidence
        assert "code_flow_summary" not in evidence


# ---------------------------------------------------------------------------
# Feature 5: Partial Fingerprints (build_sarif_evidence)
# ---------------------------------------------------------------------------


class TestPartialFingerprints:
    """build_sarif_evidence should extract partialFingerprints."""

    def test_partial_fingerprints_extracted(self) -> None:
        result = {
            "ruleId": "R1",
            "partialFingerprints": {
                "primaryLocationLineHash": "abc123",
            },
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert evidence["sarif_partial_fingerprints"] == {"primaryLocationLineHash": "abc123"}

    def test_both_fingerprints_and_partial_coexist(self) -> None:
        result = {
            "ruleId": "R1",
            "fingerprints": {"sha256/v1": "deadbeef"},
            "partialFingerprints": {"primaryLocationLineHash": "abc123"},
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "sarif_fingerprints" in evidence
        assert "sarif_partial_fingerprints" in evidence
        assert evidence["sarif_fingerprints"] == {"sha256/v1": "deadbeef"}
        assert evidence["sarif_partial_fingerprints"] == {"primaryLocationLineHash": "abc123"}

    def test_empty_partial_fingerprints_produces_no_key(self) -> None:
        result = {"ruleId": "R1", "partialFingerprints": {}}
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "sarif_partial_fingerprints" not in evidence


# ---------------------------------------------------------------------------
# Feature 6: Fix Information (build_sarif_evidence)
# ---------------------------------------------------------------------------


class TestFixInfo:
    """build_sarif_evidence should extract fix suggestions."""

    def test_fix_with_description(self) -> None:
        result = {
            "ruleId": "R1",
            "fixes": [
                {
                    "description": {"text": "Replace eval() with ast.literal_eval()"},
                    "artifactChanges": [],
                }
            ],
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert evidence["has_fix"] is True
        assert evidence["fix_description"] == "Replace eval() with ast.literal_eval()"

    def test_fix_without_description_text_still_has_fix(self) -> None:
        result = {
            "ruleId": "R1",
            "fixes": [
                {
                    "artifactChanges": [{"artifactLocation": {"uri": "file.py"}}],
                }
            ],
        }
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert evidence["has_fix"] is True
        assert "fix_description" not in evidence

    def test_empty_fixes_produces_no_keys(self) -> None:
        result = {"ruleId": "R1", "fixes": []}
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "has_fix" not in evidence
        assert "fix_description" not in evidence

    def test_no_fixes_key(self) -> None:
        result = {"ruleId": "R1"}
        evidence = build_sarif_evidence(result, rule_id="R1")
        assert "has_fix" not in evidence


# ---------------------------------------------------------------------------
# Feature 7: Suppression Handling (is_suppressed + parser integration)
# ---------------------------------------------------------------------------


class TestIsSuppressed:
    """Unit tests for the is_suppressed function."""

    def test_accepted_status_returns_suppressed(self) -> None:
        result = {"suppressions": [{"status": "accepted", "kind": "inSource"}]}
        suppressed, reason = is_suppressed(result)
        assert suppressed is True
        assert "inSource" in reason

    def test_non_accepted_status_returns_not_suppressed(self) -> None:
        result = {"suppressions": [{"status": "underReview", "kind": "inSource"}]}
        suppressed, reason = is_suppressed(result)
        assert suppressed is False
        assert reason == ""

    def test_no_suppressions_returns_not_suppressed(self) -> None:
        result = {"ruleId": "R1"}
        suppressed, reason = is_suppressed(result)
        assert suppressed is False
        assert reason == ""

    def test_justification_included_in_reason(self) -> None:
        result = {
            "suppressions": [
                {
                    "status": "accepted",
                    "kind": "inSource",
                    "justification": "False positive confirmed by security team",
                }
            ],
        }
        suppressed, reason = is_suppressed(result)
        assert suppressed is True
        assert "inSource" in reason
        assert "False positive confirmed by security team" in reason


class TestSuppressionIntegration:
    """Integration tests: parser skips suppressed results."""

    def _make_result(self, *, rule_id: str, suppressed: bool = False,
                     kind: str = "inSource", justification: str = "") -> dict:
        """Build a minimal SARIF result, optionally suppressed."""
        r: dict = {
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": f"Finding {rule_id}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"src/{rule_id.lower()}.py"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        if suppressed:
            suppression: dict = {"status": "accepted", "kind": kind}
            if justification:
                suppression["justification"] = justification
            r["suppressions"] = [suppression]
        return r

    async def test_parser_skips_suppressed_result(self) -> None:
        results = [self._make_result(rule_id="SUP001", suppressed=True)]
        sarif = _minimal_sarif(results=results)
        parser = SarifParser(_cfg())
        result = await parser.parse(sarif)
        assert len(result.findings) == 0
        assert result.stats.records_skipped >= 1
        assert result.stats.total_records_processed == 1

    async def test_mix_of_suppressed_and_non_suppressed(self) -> None:
        results = [
            self._make_result(rule_id="KEEP01", suppressed=False),
            self._make_result(rule_id="SKIP01", suppressed=True),
            self._make_result(rule_id="KEEP02", suppressed=False),
            self._make_result(rule_id="SKIP02", suppressed=True),
        ]
        sarif = _minimal_sarif(results=results)
        parser = SarifParser(_cfg())
        result = await parser.parse(sarif)
        assert len(result.findings) == 2
        assert result.stats.findings_produced == 2
        assert result.stats.records_skipped >= 2
        rule_ids = {f.evidence.get("rule_id") for f in result.findings}
        assert "KEEP01" in rule_ids
        assert "KEEP02" in rule_ids
        assert "SKIP01" not in rule_ids
        assert "SKIP02" not in rule_ids

    async def test_suppression_with_kind_and_justification(self) -> None:
        results = [
            self._make_result(
                rule_id="FP001",
                suppressed=True,
                kind="inSource",
                justification="Reviewed and confirmed false positive",
            ),
            self._make_result(rule_id="REAL001", suppressed=False),
        ]
        sarif = _minimal_sarif(results=results)
        parser = SarifParser(_cfg())
        result = await parser.parse(sarif)
        assert len(result.findings) == 1
        assert result.findings[0].evidence.get("rule_id") == "REAL001"
        assert result.stats.records_skipped >= 1
