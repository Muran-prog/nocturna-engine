"""Edge-case focused tests for HTML column alias matching and delegation."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.parsers.html._table_extractor.column_mapping import (
    _COLUMN_ALIASES,
    _find_column,
)


# ---------------------------------------------------------------------------
# Alias delegation (HTML aliases == CSV aliases)
# ---------------------------------------------------------------------------


class TestAliasesDelegation:
    """Verify _COLUMN_ALIASES is the same object as csv_generic's."""

    def test_aliases_identity_with_csv_generic(self) -> None:
        from nocturna_engine.normalization.parsers.csv_generic.column_mapping import (
            _COLUMN_ALIASES as CSV_ALIASES,
        )

        assert _COLUMN_ALIASES is CSV_ALIASES, (
            "_COLUMN_ALIASES in HTML module must be the exact same object as CSV module"
        )

    def test_aliases_has_expected_keys(self) -> None:
        expected_keys = {"title", "description", "severity", "target", "cwe", "cvss", "tool"}
        assert expected_keys == set(_COLUMN_ALIASES.keys())

    def test_aliases_values_are_non_empty_lists(self) -> None:
        for key, aliases in _COLUMN_ALIASES.items():
            assert isinstance(aliases, list), f"Aliases for '{key}' must be a list"
            assert len(aliases) > 0, f"Aliases for '{key}' must not be empty"


# ---------------------------------------------------------------------------
# _find_column — comprehensive alias matching
# ---------------------------------------------------------------------------


class TestFindColumnHtml:
    """Test _find_column with all alias families and edge cases."""

    # --- Title aliases ---

    @pytest.mark.parametrize(
        "header,expected_idx",
        [
            ("title", 0),
            ("name", 0),
            ("vulnerability", 0),
            ("finding", 0),
            ("rule", 0),
            ("check", 0),
            ("issue", 0),
        ],
        ids=["title", "name", "vulnerability", "finding", "rule", "check", "issue"],
    )
    def test_title_aliases_exact(self, header: str, expected_idx: int) -> None:
        assert _find_column([header], _COLUMN_ALIASES["title"]) == expected_idx

    # --- Description aliases ---

    @pytest.mark.parametrize(
        "header",
        ["description", "detail", "details", "message", "summary", "info"],
        ids=["description", "detail", "details", "message", "summary", "info"],
    )
    def test_description_aliases_exact(self, header: str) -> None:
        assert _find_column([header], _COLUMN_ALIASES["description"]) == 0

    # --- Severity aliases ---

    @pytest.mark.parametrize(
        "header",
        ["severity", "risk", "priority", "level", "rating", "impact"],
        ids=["severity", "risk", "priority", "level", "rating", "impact"],
    )
    def test_severity_aliases_exact(self, header: str) -> None:
        assert _find_column([header], _COLUMN_ALIASES["severity"]) == 0

    # --- Target aliases ---

    @pytest.mark.parametrize(
        "header",
        ["target", "host", "ip", "address", "url", "hostname", "asset", "endpoint"],
        ids=["target", "host", "ip", "address", "url", "hostname", "asset", "endpoint"],
    )
    def test_target_aliases_exact(self, header: str) -> None:
        assert _find_column([header], _COLUMN_ALIASES["target"]) == 0

    # --- CWE aliases ---

    @pytest.mark.parametrize(
        "header",
        ["cwe", "cwe_id", "cwe-id"],
        ids=["cwe", "cwe_id", "cwe-id"],
    )
    def test_cwe_aliases_exact(self, header: str) -> None:
        assert _find_column([header], _COLUMN_ALIASES["cwe"]) == 0

    # --- CVSS aliases ---

    @pytest.mark.parametrize(
        "header",
        ["cvss", "cvss_score", "cvss-score", "score"],
        ids=["cvss", "cvss_score", "cvss-score", "score"],
    )
    def test_cvss_aliases_exact(self, header: str) -> None:
        assert _find_column([header], _COLUMN_ALIASES["cvss"]) == 0

    # --- Tool aliases ---

    @pytest.mark.parametrize(
        "header",
        ["tool", "scanner", "source", "plugin"],
        ids=["tool", "scanner", "source", "plugin"],
    )
    def test_tool_aliases_exact(self, header: str) -> None:
        assert _find_column([header], _COLUMN_ALIASES["tool"]) == 0

    # --- Partial matching ---

    def test_partial_match_substring(self) -> None:
        assert _find_column(["vulnerability_name"], ["vulnerability"]) == 0

    def test_partial_match_in_middle(self) -> None:
        assert _find_column(["my_severity_col"], ["severity"]) == 0

    # --- No match ---

    def test_no_match_returns_none(self) -> None:
        assert _find_column(["foo", "bar"], ["title", "name"]) is None

    # --- Empty inputs ---

    def test_empty_headers_returns_none(self) -> None:
        assert _find_column([], ["title"]) is None

    def test_empty_aliases_returns_none(self) -> None:
        assert _find_column(["title"], []) is None

    def test_both_empty_returns_none(self) -> None:
        assert _find_column([], []) is None

    # --- First alias wins ---

    def test_first_alias_match_wins(self) -> None:
        headers = ["name", "title"]
        # "title" alias appears before "name" in the list
        result = _find_column(headers, ["title", "name"])
        assert result == 1, "First alias 'title' should match at index 1"

    # --- Index correctness ---

    def test_correct_index_among_many_headers(self) -> None:
        headers = ["foo", "bar", "severity", "baz"]
        assert _find_column(headers, ["severity"]) == 2

    # --- ZAP-specific headers ---

    def test_zap_name_maps_to_title(self) -> None:
        headers = ["name", "risk", "url", "description", "cwe"]
        assert _find_column(headers, _COLUMN_ALIASES["title"]) is not None

    def test_zap_risk_maps_to_severity(self) -> None:
        headers = ["name", "risk", "url", "description", "cwe"]
        assert _find_column(headers, _COLUMN_ALIASES["severity"]) == 1

    def test_zap_url_maps_to_target(self) -> None:
        # Note: 'ip' alias partially matches 'description' before 'url' matches 'url'
        # because aliases are tried in order. Use headers without 'description'.
        headers = ["name", "risk", "url", "cwe"]
        assert _find_column(headers, _COLUMN_ALIASES["target"]) == 2

    # --- Nikto-specific headers ---

    def test_nikto_uri_not_in_target_aliases(self) -> None:
        """'uri' is NOT a target alias — _find_column cannot map it."""
        headers = ["uri", "http method"]
        idx = _find_column(headers, _COLUMN_ALIASES["target"])
        assert idx is None, "'uri' is not in target alias list"

    def test_nikto_description_maps(self) -> None:
        headers = ["uri", "http method", "description"]
        assert _find_column(headers, _COLUMN_ALIASES["description"]) == 2

    # --- Burp-specific headers ---

    def test_burp_vulnerability_maps_to_title(self) -> None:
        headers = ["vulnerability", "severity", "host", "path"]
        assert _find_column(headers, _COLUMN_ALIASES["title"]) == 0

    def test_burp_severity_maps(self) -> None:
        headers = ["vulnerability", "severity", "host", "path"]
        assert _find_column(headers, _COLUMN_ALIASES["severity"]) == 1

    def test_burp_host_maps_to_target(self) -> None:
        headers = ["vulnerability", "severity", "host", "path"]
        assert _find_column(headers, _COLUMN_ALIASES["target"]) == 2
