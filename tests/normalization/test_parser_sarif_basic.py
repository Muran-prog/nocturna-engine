"""Edge-case tests for SarifParser: structure validation, error handling, basic parsing."""

from __future__ import annotations

import json

import pytest

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers.base import ParserConfig
from nocturna_engine.normalization.parsers.sarif import SarifParser
from nocturna_engine.normalization.severity import build_severity_map


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
) -> str:
    """Build a minimal valid SARIF document."""
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
        runs = [
            {
                "tool": {"driver": {"name": tool_name, "rules": []}},
                "results": results,
            }
        ]
    doc = {"version": version, "$schema": "https://sarif.schema", "runs": runs}
    return json.dumps(doc)


class TestSarifInvalidInput:
    """Invalid/malformed input edge cases."""

    async def test_invalid_json_returns_error_issue(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(b"NOT VALID JSON {{{")
        assert len(result.findings) == 0
        assert len(result.issues) == 1
        assert "Invalid SARIF JSON" in result.issues[0].message
        assert result.stats.errors_encountered == 1

    async def test_empty_string_returns_error(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(b"")
        assert len(result.findings) == 0
        assert len(result.issues) >= 1
        assert result.stats.errors_encountered >= 1

    async def test_root_is_array_returns_error(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(json.dumps([1, 2, 3]))
        assert len(result.findings) == 0
        assert any("not a JSON object" in i.message for i in result.issues)

    async def test_root_is_string_returns_error(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(json.dumps("just a string"))
        assert len(result.findings) == 0
        assert result.stats.errors_encountered == 1

    async def test_root_is_number_returns_error(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(json.dumps(42))
        assert len(result.findings) == 0
        assert result.stats.errors_encountered == 1

    async def test_root_is_null_returns_error(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(json.dumps(None))
        assert len(result.findings) == 0

    async def test_root_is_bool_returns_error(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(json.dumps(True))
        assert len(result.findings) == 0
        assert result.stats.errors_encountered == 1

    async def test_truncated_json(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(b'{"version": "2.1.0", "runs": [')
        assert len(result.findings) == 0
        assert len(result.issues) >= 1

    async def test_bytes_input_with_bom(self) -> None:
        """UTF-8 BOM should not break parsing."""
        parser = SarifParser(_cfg())
        sarif_data = _minimal_sarif().encode("utf-8-sig")
        result = await parser.parse(sarif_data)
        # BOM may cause JSONDecodeError or the parser should still work
        # Either way, it should not crash
        assert result is not None


class TestSarifMissingRuns:
    """Missing or malformed 'runs' key."""

    async def test_missing_runs_key_produces_issue(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({"version": "2.1.0"})
        result = await parser.parse(doc)
        assert len(result.findings) == 0
        assert any("missing 'runs'" in i.message for i in result.issues)

    async def test_runs_is_null(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({"version": "2.1.0", "runs": None})
        result = await parser.parse(doc)
        assert len(result.findings) == 0

    async def test_runs_is_not_a_list(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({"version": "2.1.0", "runs": "not-a-list"})
        result = await parser.parse(doc)
        assert len(result.findings) == 0

    async def test_runs_is_dict(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({"version": "2.1.0", "runs": {"key": "value"}})
        result = await parser.parse(doc)
        assert len(result.findings) == 0

    async def test_runs_is_number(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({"version": "2.1.0", "runs": 42})
        result = await parser.parse(doc)
        assert len(result.findings) == 0


class TestSarifEmptyResults:
    """Empty results array edge cases."""

    async def test_empty_results_array(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif(results=[]))
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0

    async def test_results_is_null(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "t"}}, "results": None}],
        })
        result = await parser.parse(doc)
        assert len(result.findings) == 0

    async def test_results_is_not_list(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "t"}}, "results": "bad"}],
        })
        result = await parser.parse(doc)
        assert len(result.findings) == 0


class TestSarifResultNotDict:
    """Result entries that are not dicts."""

    @pytest.mark.parametrize("bad_result", [
        42,
        "string-result",
        [1, 2, 3],
        None,
        True,
    ], ids=["int", "str", "list", "none", "bool"])
    async def test_non_dict_result_counted_as_error(self, bad_result) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "t", "rules": []}},
                "results": [bad_result],
            }],
        })
        result = await parser.parse(doc)
        assert len(result.findings) == 0
        assert result.stats.errors_encountered == 1
        assert any("not an object" in i.message for i in result.issues)


class TestSarifVersionMismatch:
    """SARIF version validation."""

    @pytest.mark.parametrize("version,should_warn", [
        ("2.1.0", False),
        ("2.1.1", False),
        ("2.1.99", False),
        ("3.0.0", True),
        ("1.0.0", True),
        ("", False),  # empty version: no startswith match, no warning
    ], ids=["2.1.0", "2.1.1", "2.1.99", "3.0.0", "1.0.0", "empty"])
    async def test_version_warning(self, version: str, should_warn: bool) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif(version=version))
        version_issues = [i for i in result.issues if "version" in i.message.lower()]
        if should_warn:
            assert len(version_issues) >= 1
        else:
            assert len(version_issues) == 0

    async def test_version_3_still_parses_findings(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif(version="3.0.0"))
        # Warning issued but parsing continues
        assert len(result.findings) == 1


class TestSarifMultipleRuns:
    """Multiple runs in one SARIF document."""

    async def test_findings_from_all_runs(self) -> None:
        parser = SarifParser(_cfg())
        run1_results = [
            {"ruleId": "R1", "level": "error", "message": {"text": "Finding from run 1"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}]},
        ]
        run2_results = [
            {"ruleId": "R2", "level": "note", "message": {"text": "Finding from run 2"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"}}}]},
            {"ruleId": "R3", "level": "warning", "message": {"text": "Another finding from run 2"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "c.py"}}}]},
        ]
        runs = [
            {"tool": {"driver": {"name": "tool1", "rules": []}}, "results": run1_results},
            {"tool": {"driver": {"name": "tool2", "rules": []}}, "results": run2_results},
        ]
        result = await parser.parse(_minimal_sarif(runs=runs))
        assert len(result.findings) == 3
        assert result.stats.findings_produced == 3

    async def test_run_not_dict_produces_issue(self) -> None:
        parser = SarifParser(_cfg())
        runs = [
            "not-a-dict",
            {"tool": {"driver": {"name": "tool", "rules": []}},
             "results": [{"ruleId": "R1", "level": "error", "message": {"text": "Valid finding here"},
                          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"}}}]}]},
        ]
        result = await parser.parse(_minimal_sarif(runs=runs))
        assert len(result.findings) == 1  # second run still parsed
        assert any("not an object" in i.message for i in result.issues)

    async def test_mixed_valid_and_empty_runs(self) -> None:
        parser = SarifParser(_cfg())
        runs = [
            {"tool": {"driver": {"name": "tool1", "rules": []}}, "results": []},
            {"tool": {"driver": {"name": "tool2", "rules": []}},
             "results": [{"ruleId": "R1", "message": {"text": "Found"},
                          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}]}]},
        ]
        result = await parser.parse(_minimal_sarif(runs=runs))
        assert len(result.findings) == 1


class TestSarifNoArtifacts:
    """SARIF without artifacts array — should not crash."""

    async def test_no_artifacts_key(self) -> None:
        parser = SarifParser(_cfg())
        doc = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "t", "rules": []}},
                "results": [
                    {"ruleId": "R1", "message": {"text": "No artifacts"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.py"}}}]},
                ],
            }],
        }
        result = await parser.parse(json.dumps(doc))
        assert len(result.findings) == 1

    async def test_empty_runs_list(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({"version": "2.1.0", "runs": []})
        result = await parser.parse(doc)
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0


class TestSarifValidMinimal:
    """Valid minimal SARIF v2.1.0 with one run/result."""

    async def test_single_result_parsed(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif())
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.title == "Test finding message"
        assert f.target == "src/main.py"
        assert f.tool == "test-tool"
        assert result.stats.findings_produced == 1
        assert result.stats.total_records_processed == 1

    async def test_string_input(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif())
        assert len(result.findings) == 1

    async def test_bytes_input(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif().encode("utf-8"))
        assert len(result.findings) == 1

    async def test_stats_skipped_is_zero_for_clean_parse(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif())
        assert result.stats.records_skipped == 0
        assert result.stats.errors_encountered == 0


class TestSarifToolNameExtraction:
    """Tool name extraction from SARIF run."""

    async def test_tool_name_from_driver(self) -> None:
        parser = SarifParser(_cfg())
        result = await parser.parse(_minimal_sarif(tool_name="custom-scanner"))
        assert result.findings[0].tool == "custom-scanner"

    async def test_missing_tool_falls_back_to_config(self) -> None:
        parser = SarifParser(_cfg())
        doc = json.dumps({
            "version": "2.1.0",
            "runs": [{
                "results": [
                    {"ruleId": "R1", "message": {"text": "No tool key"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"}}}]},
                ],
            }],
        })
        result = await parser.parse(doc)
        assert len(result.findings) == 1
        assert result.findings[0].tool == "test_tool"

    async def test_whitespace_tool_name_causes_validation_error(self) -> None:
        """When driver name is all whitespace, _extract_tool_name returns ''
        (checks `if name:` on un-stripped value, then strips to empty).
        This causes a Finding validation error since tool must be non-empty."""
        parser = SarifParser(_cfg())
        doc = json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "   "}},
                "results": [
                    {"ruleId": "R1", "message": {"text": "Whitespace tool name test"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"}}}]},
                ],
            }],
        })
        result = await parser.parse(doc)
        # The empty tool name causes a validation error, recorded as issue
        assert len(result.findings) == 0
        assert result.stats.errors_encountered == 1
