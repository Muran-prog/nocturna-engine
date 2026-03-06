"""Edge-case focused tests for nocturna_engine.normalization.severity."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.errors import SeverityMappingError
from nocturna_engine.normalization.severity import (
    SeverityMap,
    _DEFAULT_SEVERITY_TABLE,
    build_severity_map,
    merge_severities,
)


# ---------------------------------------------------------------------------
# _DEFAULT_SEVERITY_TABLE completeness
# ---------------------------------------------------------------------------


class TestDefaultSeverityTable:
    """Verify _DEFAULT_SEVERITY_TABLE has all expected entries and values."""

    EXPECTED_ENTRIES: dict[str, SeverityLevel] = {
        "critical": SeverityLevel.CRITICAL,
        "crit": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "med": SeverityLevel.MEDIUM,
        "moderate": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
        "informational": SeverityLevel.INFO,
        "information": SeverityLevel.INFO,
        "none": SeverityLevel.INFO,
        "unknown": SeverityLevel.INFO,
        "error": SeverityLevel.HIGH,
        "warning": SeverityLevel.MEDIUM,
        "note": SeverityLevel.LOW,
        "urgent": SeverityLevel.CRITICAL,
        "important": SeverityLevel.HIGH,
        "minor": SeverityLevel.LOW,
        "trivial": SeverityLevel.INFO,
    }

    def test_table_length_matches(self) -> None:
        assert len(_DEFAULT_SEVERITY_TABLE) == len(self.EXPECTED_ENTRIES)

    @pytest.mark.parametrize(
        "key,expected",
        list(EXPECTED_ENTRIES.items()),
        ids=list(EXPECTED_ENTRIES.keys()),
    )
    def test_each_entry_value(self, key: str, expected: SeverityLevel) -> None:
        assert _DEFAULT_SEVERITY_TABLE[key] is expected

    def test_all_keys_lowercase(self) -> None:
        for key in _DEFAULT_SEVERITY_TABLE:
            assert key == key.lower(), f"Key {key!r} is not lowercase"

    def test_no_extra_keys(self) -> None:
        assert set(_DEFAULT_SEVERITY_TABLE.keys()) == set(self.EXPECTED_ENTRIES.keys())

    def test_all_values_are_severity_levels(self) -> None:
        for key, val in _DEFAULT_SEVERITY_TABLE.items():
            assert isinstance(val, SeverityLevel), f"{key!r} maps to non-SeverityLevel"

    def test_table_is_dict(self) -> None:
        assert isinstance(_DEFAULT_SEVERITY_TABLE, dict)

    def test_every_severity_level_represented(self) -> None:
        """Every SeverityLevel member should appear at least once in the table."""
        present = set(_DEFAULT_SEVERITY_TABLE.values())
        for member in SeverityLevel:
            assert member in present, f"{member} not represented in table"


# ---------------------------------------------------------------------------
# SeverityMap model validation
# ---------------------------------------------------------------------------


class TestSeverityMapModel:
    """Pydantic model config edge cases."""

    def test_extra_field_forbidden(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            SeverityMap(unknown_field="boom")  # type: ignore[call-arg]

    def test_validate_assignment_rejects_bad_type(self) -> None:
        sm = SeverityMap()
        with pytest.raises(ValidationError):
            sm.strict = "not_a_bool"  # type: ignore[assignment]

    def test_validate_assignment_rejects_bad_fallback(self) -> None:
        sm = SeverityMap()
        with pytest.raises(ValidationError):
            sm.fallback_severity = "not_a_severity"  # type: ignore[assignment]

    def test_default_fallback_is_info(self) -> None:
        sm = SeverityMap()
        assert sm.fallback_severity is SeverityLevel.INFO

    def test_default_strict_is_false(self) -> None:
        sm = SeverityMap()
        assert sm.strict is False

    def test_default_table_is_copy(self) -> None:
        """Default table should be a copy, not a reference to the module-level dict."""
        sm = SeverityMap()
        assert sm.default_table == _DEFAULT_SEVERITY_TABLE
        assert sm.default_table is not _DEFAULT_SEVERITY_TABLE

    def test_default_tool_overrides_empty(self) -> None:
        sm = SeverityMap()
        assert sm.tool_overrides == {}

    def test_custom_default_table(self) -> None:
        custom = {"custom_key": SeverityLevel.HIGH}
        sm = SeverityMap(default_table=custom)
        assert sm.default_table == custom

    def test_empty_default_table(self) -> None:
        sm = SeverityMap(default_table={})
        assert sm.default_table == {}

    def test_multiple_tool_overrides(self) -> None:
        overrides = {
            "tool_a": {"x": SeverityLevel.HIGH},
            "tool_b": {"y": SeverityLevel.LOW},
        }
        sm = SeverityMap(tool_overrides=overrides)
        assert len(sm.tool_overrides) == 2

    def test_mutation_after_construction(self) -> None:
        """Validate assignment allows valid mutations."""
        sm = SeverityMap()
        sm.strict = True
        assert sm.strict is True
        sm.fallback_severity = SeverityLevel.CRITICAL
        assert sm.fallback_severity is SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# SeverityMap.resolve
# ---------------------------------------------------------------------------


class TestSeverityMapResolve:
    """Exhaustive resolve() edge-case tests."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", SeverityLevel.CRITICAL),
            ("crit", SeverityLevel.CRITICAL),
            ("high", SeverityLevel.HIGH),
            ("medium", SeverityLevel.MEDIUM),
            ("med", SeverityLevel.MEDIUM),
            ("moderate", SeverityLevel.MEDIUM),
            ("low", SeverityLevel.LOW),
            ("info", SeverityLevel.INFO),
            ("informational", SeverityLevel.INFO),
            ("information", SeverityLevel.INFO),
            ("none", SeverityLevel.INFO),
            ("unknown", SeverityLevel.INFO),
            ("error", SeverityLevel.HIGH),
            ("warning", SeverityLevel.MEDIUM),
            ("note", SeverityLevel.LOW),
            ("urgent", SeverityLevel.CRITICAL),
            ("important", SeverityLevel.HIGH),
            ("minor", SeverityLevel.LOW),
            ("trivial", SeverityLevel.INFO),
        ],
        ids=lambda p: str(p) if isinstance(p, str) else "",
    )
    def test_default_table_lookup(self, raw: str, expected: SeverityLevel) -> None:
        sm = SeverityMap()
        assert sm.resolve(raw) is expected

    # -- Case insensitivity --

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CRITICAL", SeverityLevel.CRITICAL),
            ("Critical", SeverityLevel.CRITICAL),
            ("cRiTiCaL", SeverityLevel.CRITICAL),
            ("HIGH", SeverityLevel.HIGH),
            ("High", SeverityLevel.HIGH),
            ("MEDIUM", SeverityLevel.MEDIUM),
            ("LOW", SeverityLevel.LOW),
            ("INFO", SeverityLevel.INFO),
            ("WARNING", SeverityLevel.MEDIUM),
            ("ERROR", SeverityLevel.HIGH),
            ("NOTE", SeverityLevel.LOW),
            ("URGENT", SeverityLevel.CRITICAL),
            ("Informational", SeverityLevel.INFO),
            ("TRIVIAL", SeverityLevel.INFO),
        ],
    )
    def test_case_insensitive(self, raw: str, expected: SeverityLevel) -> None:
        sm = SeverityMap()
        assert sm.resolve(raw) is expected

    # -- Whitespace stripping --

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("  critical  ", SeverityLevel.CRITICAL),
            ("\thigh\n", SeverityLevel.HIGH),
            ("  low ", SeverityLevel.LOW),
            ("\r\nmedium\r\n", SeverityLevel.MEDIUM),
            (" \t info \t ", SeverityLevel.INFO),
            ("  \n  warning  \r  ", SeverityLevel.MEDIUM),
        ],
    )
    def test_whitespace_stripped(self, raw: str, expected: SeverityLevel) -> None:
        sm = SeverityMap()
        assert sm.resolve(raw) is expected

    # -- Empty string --

    def test_empty_string_strict_raises(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="Empty severity value"):
            sm.resolve("")

    def test_empty_string_non_strict_returns_fallback(self) -> None:
        sm = SeverityMap(strict=False, fallback_severity=SeverityLevel.MEDIUM)
        assert sm.resolve("") is SeverityLevel.MEDIUM

    def test_whitespace_only_strict_raises(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="Empty severity value"):
            sm.resolve("   ")

    def test_whitespace_only_non_strict_returns_fallback(self) -> None:
        sm = SeverityMap(strict=False)
        assert sm.resolve("   ") is SeverityLevel.INFO

    def test_tabs_only_strict_raises(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="Empty severity value"):
            sm.resolve("\t\t")

    def test_newlines_only_non_strict_returns_fallback(self) -> None:
        sm = SeverityMap(strict=False, fallback_severity=SeverityLevel.LOW)
        assert sm.resolve("\n\n") is SeverityLevel.LOW

    # -- Empty string strict includes tool_name in message --

    def test_empty_string_strict_includes_tool_name(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="tool='scanner'"):
            sm.resolve("", tool_name="scanner")

    def test_empty_string_strict_tool_none_in_message(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="tool=None"):
            sm.resolve("")

    # -- Unknown severity string --

    def test_unknown_strict_raises(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="Unmapped severity"):
            sm.resolve("xyzzy_not_a_severity")

    def test_unknown_non_strict_returns_fallback(self) -> None:
        sm = SeverityMap(fallback_severity=SeverityLevel.HIGH)
        assert sm.resolve("xyzzy_not_a_severity") is SeverityLevel.HIGH

    def test_unknown_strict_includes_tool_name_in_error(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="tool='mytool'"):
            sm.resolve("bogus", tool_name="mytool")

    def test_unknown_strict_includes_raw_severity_in_error(self) -> None:
        sm = SeverityMap(strict=True)
        with pytest.raises(SeverityMappingError, match="'custom_weird_sev'"):
            sm.resolve("custom_weird_sev")

    # -- tool_overrides --

    def test_tool_override_takes_priority(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "bandit": {"high": SeverityLevel.MEDIUM},
            },
        )
        assert sm.resolve("high", tool_name="bandit") is SeverityLevel.MEDIUM

    def test_tool_override_falls_through_to_default(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "bandit": {"high": SeverityLevel.MEDIUM},
            },
        )
        assert sm.resolve("critical", tool_name="bandit") is SeverityLevel.CRITICAL

    def test_tool_not_in_overrides_uses_default(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "bandit": {"high": SeverityLevel.MEDIUM},
            },
        )
        assert sm.resolve("high", tool_name="semgrep") is SeverityLevel.HIGH

    def test_tool_override_case_insensitive_tool_name(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "bandit": {"warning": SeverityLevel.CRITICAL},
            },
        )
        assert sm.resolve("warning", tool_name="BANDIT") is SeverityLevel.CRITICAL

    def test_tool_override_case_insensitive_severity(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "bandit": {"custom_sev": SeverityLevel.HIGH},
            },
        )
        assert sm.resolve("CUSTOM_SEV", tool_name="bandit") is SeverityLevel.HIGH

    def test_tool_name_none_skips_overrides(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "bandit": {"high": SeverityLevel.LOW},
            },
        )
        assert sm.resolve("high", tool_name=None) is SeverityLevel.HIGH

    def test_tool_override_whitespace_tool_name(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "bandit": {"high": SeverityLevel.LOW},
            },
        )
        assert sm.resolve("high", tool_name="  bandit  ") is SeverityLevel.LOW

    def test_tool_override_empty_tool_name_treated_as_key(self) -> None:
        """Empty string tool_name is still passed to overrides lookup."""
        sm = SeverityMap(
            tool_overrides={
                "": {"high": SeverityLevel.LOW},
            },
        )
        assert sm.resolve("high", tool_name="") is SeverityLevel.LOW

    def test_multiple_tool_overrides_isolated(self) -> None:
        sm = SeverityMap(
            tool_overrides={
                "tool_a": {"high": SeverityLevel.CRITICAL},
                "tool_b": {"high": SeverityLevel.LOW},
            },
        )
        assert sm.resolve("high", tool_name="tool_a") is SeverityLevel.CRITICAL
        assert sm.resolve("high", tool_name="tool_b") is SeverityLevel.LOW

    # -- Direct SeverityLevel value match --

    @pytest.mark.parametrize(
        "raw",
        ["critical", "high", "medium", "low", "info"],
    )
    def test_direct_severity_level_value_match(self, raw: str) -> None:
        """Empty default table forces SeverityLevel() fallback path."""
        sm = SeverityMap(default_table={})
        result = sm.resolve(raw)
        assert result == SeverityLevel(raw)

    def test_direct_severity_level_match_not_in_table(self) -> None:
        sm = SeverityMap(default_table={})
        assert sm.resolve("info") is SeverityLevel.INFO

    def test_direct_severity_level_match_after_empty_override(self) -> None:
        """If tool override exists but key not found, then default table empty,
        still falls back to SeverityLevel()."""
        sm = SeverityMap(
            default_table={},
            tool_overrides={"mytool": {"x": SeverityLevel.HIGH}},
        )
        assert sm.resolve("critical", tool_name="mytool") is SeverityLevel.CRITICAL

    # -- Fallback severity customization --

    def test_custom_fallback_severity(self) -> None:
        sm = SeverityMap(fallback_severity=SeverityLevel.CRITICAL)
        assert sm.resolve("completely_unknown") is SeverityLevel.CRITICAL

    @pytest.mark.parametrize("level", list(SeverityLevel))
    def test_fallback_for_each_severity_level(self, level: SeverityLevel) -> None:
        sm = SeverityMap(fallback_severity=level)
        assert sm.resolve("zzz_unknown_zzz") is level

    # -- Non-string coercion via str() --

    def test_resolve_integer_coerced_via_str(self) -> None:
        """resolve() calls str() on raw_severity; integer 123 becomes '123'."""
        sm = SeverityMap(default_table={"123": SeverityLevel.HIGH})
        assert sm.resolve("123") is SeverityLevel.HIGH

    # -- Priority: override > default > SeverityLevel > fallback --

    def test_resolution_order_override_wins_over_default(self) -> None:
        sm = SeverityMap(
            default_table={"high": SeverityLevel.HIGH},
            tool_overrides={"tool": {"high": SeverityLevel.LOW}},
        )
        assert sm.resolve("high", tool_name="tool") is SeverityLevel.LOW

    def test_resolution_order_default_wins_over_severity_level(self) -> None:
        sm = SeverityMap(
            default_table={"critical": SeverityLevel.LOW},
        )
        assert sm.resolve("critical") is SeverityLevel.LOW


# ---------------------------------------------------------------------------
# SeverityMap.resolve_cvss
# ---------------------------------------------------------------------------


class TestSeverityMapResolveCvss:
    """Boundary-value tests for CVSS score mapping."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            # INFO: < 0.1
            (0.0, SeverityLevel.INFO),
            (0.09, SeverityLevel.INFO),
            (0.099, SeverityLevel.INFO),
            # LOW: 0.1 <= score < 4.0
            (0.1, SeverityLevel.LOW),
            (0.11, SeverityLevel.LOW),
            (2.0, SeverityLevel.LOW),
            (3.9, SeverityLevel.LOW),
            (3.99, SeverityLevel.LOW),
            # MEDIUM: 4.0 <= score < 7.0
            (4.0, SeverityLevel.MEDIUM),
            (4.01, SeverityLevel.MEDIUM),
            (5.5, SeverityLevel.MEDIUM),
            (6.9, SeverityLevel.MEDIUM),
            (6.99, SeverityLevel.MEDIUM),
            # HIGH: 7.0 <= score < 9.0
            (7.0, SeverityLevel.HIGH),
            (7.01, SeverityLevel.HIGH),
            (8.0, SeverityLevel.HIGH),
            (8.9, SeverityLevel.HIGH),
            (8.99, SeverityLevel.HIGH),
            # CRITICAL: 9.0 <= score <= 10.0
            (9.0, SeverityLevel.CRITICAL),
            (9.01, SeverityLevel.CRITICAL),
            (9.5, SeverityLevel.CRITICAL),
            (9.99, SeverityLevel.CRITICAL),
            (10.0, SeverityLevel.CRITICAL),
        ],
    )
    def test_cvss_boundary(self, score: float, expected: SeverityLevel) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(score) is expected

    def test_cvss_negative_raises(self) -> None:
        """Negative scores should raise ValueError (out of CVSS range)."""
        sm = SeverityMap()
        with pytest.raises(ValueError, match="between 0.0 and 10.0"):
            sm.resolve_cvss(-1.0)

    def test_cvss_above_10_raises(self) -> None:
        """Scores above 10 should raise ValueError (out of CVSS range)."""
        sm = SeverityMap()
        with pytest.raises(ValueError, match="between 0.0 and 10.0"):
            sm.resolve_cvss(15.0)

    def test_cvss_exact_boundary_0_1(self) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(0.1) is SeverityLevel.LOW
        assert sm.resolve_cvss(0.09999) is SeverityLevel.INFO

    def test_cvss_exact_boundary_4_0(self) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(4.0) is SeverityLevel.MEDIUM
        assert sm.resolve_cvss(3.99999) is SeverityLevel.LOW

    def test_cvss_exact_boundary_7_0(self) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(7.0) is SeverityLevel.HIGH
        assert sm.resolve_cvss(6.99999) is SeverityLevel.MEDIUM

    def test_cvss_exact_boundary_9_0(self) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(9.0) is SeverityLevel.CRITICAL
        assert sm.resolve_cvss(8.99999) is SeverityLevel.HIGH

    def test_cvss_zero_exactly(self) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(0.0) is SeverityLevel.INFO

    def test_cvss_very_small_positive(self) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(0.001) is SeverityLevel.INFO

    def test_cvss_ten_exactly(self) -> None:
        sm = SeverityMap()
        assert sm.resolve_cvss(10.0) is SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# build_severity_map
# ---------------------------------------------------------------------------


class TestBuildSeverityMap:
    """Factory function edge cases."""

    def test_no_args_returns_default_table(self) -> None:
        sm = build_severity_map()
        assert sm.default_table == _DEFAULT_SEVERITY_TABLE
        assert sm.tool_overrides == {}
        assert sm.fallback_severity is SeverityLevel.INFO
        assert sm.strict is False

    def test_extra_mappings_adds_entries(self) -> None:
        sm = build_severity_map(extra_mappings={"custom": SeverityLevel.HIGH})
        assert sm.default_table["custom"] is SeverityLevel.HIGH
        # Original entries still present.
        assert sm.default_table["critical"] is SeverityLevel.CRITICAL

    def test_extra_mappings_overrides_existing(self) -> None:
        """Extra mappings can override existing default table entries."""
        sm = build_severity_map(
            extra_mappings={"critical": SeverityLevel.LOW},
        )
        assert sm.default_table["critical"] is SeverityLevel.LOW

    def test_overrides_passed_through(self) -> None:
        overrides = {"nmap": {"open": SeverityLevel.HIGH}}
        sm = build_severity_map(overrides=overrides)
        assert sm.tool_overrides == overrides

    def test_strict_flag_passed(self) -> None:
        sm = build_severity_map(strict=True)
        assert sm.strict is True

    def test_custom_fallback(self) -> None:
        sm = build_severity_map(fallback=SeverityLevel.CRITICAL)
        assert sm.fallback_severity is SeverityLevel.CRITICAL

    def test_all_params_combined(self) -> None:
        sm = build_severity_map(
            overrides={"tool1": {"x": SeverityLevel.LOW}},
            extra_mappings={"custom_sev": SeverityLevel.MEDIUM},
            fallback=SeverityLevel.HIGH,
            strict=True,
        )
        assert sm.strict is True
        assert sm.fallback_severity is SeverityLevel.HIGH
        assert "custom_sev" in sm.default_table
        assert "tool1" in sm.tool_overrides

    def test_default_table_is_independent_copy(self) -> None:
        """build_severity_map creates a fresh copy each call."""
        sm1 = build_severity_map()
        sm2 = build_severity_map()
        sm1.default_table["injected"] = SeverityLevel.CRITICAL
        assert "injected" not in sm2.default_table

    def test_overrides_none_becomes_empty_dict(self) -> None:
        sm = build_severity_map(overrides=None)
        assert sm.tool_overrides == {}

    def test_extra_mappings_none_no_effect(self) -> None:
        sm = build_severity_map(extra_mappings=None)
        assert sm.default_table == _DEFAULT_SEVERITY_TABLE

    def test_extra_mappings_empty_dict_no_effect(self) -> None:
        sm = build_severity_map(extra_mappings={})
        assert sm.default_table == _DEFAULT_SEVERITY_TABLE

    def test_build_produces_usable_resolve(self) -> None:
        """End-to-end: build then resolve."""
        sm = build_severity_map(
            extra_mappings={"custom_high": SeverityLevel.HIGH},
            strict=True,
        )
        assert sm.resolve("custom_high") is SeverityLevel.HIGH
        assert sm.resolve("critical") is SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# merge_severities
# ---------------------------------------------------------------------------


class TestMergeSeverities:
    """Verify highest-severity-wins merge logic."""

    def test_empty_list_returns_info(self) -> None:
        assert merge_severities([]) is SeverityLevel.INFO

    @pytest.mark.parametrize("level", list(SeverityLevel), ids=lambda s: s.name)
    def test_single_element(self, level: SeverityLevel) -> None:
        assert merge_severities([level]) is level

    @pytest.mark.parametrize(
        "levels,expected",
        [
            ([SeverityLevel.LOW, SeverityLevel.HIGH], SeverityLevel.HIGH),
            ([SeverityLevel.HIGH, SeverityLevel.LOW], SeverityLevel.HIGH),
            ([SeverityLevel.INFO, SeverityLevel.CRITICAL], SeverityLevel.CRITICAL),
            ([SeverityLevel.CRITICAL, SeverityLevel.INFO], SeverityLevel.CRITICAL),
            ([SeverityLevel.MEDIUM, SeverityLevel.LOW], SeverityLevel.MEDIUM),
            ([SeverityLevel.LOW, SeverityLevel.MEDIUM], SeverityLevel.MEDIUM),
            ([SeverityLevel.HIGH, SeverityLevel.CRITICAL], SeverityLevel.CRITICAL),
            ([SeverityLevel.INFO, SeverityLevel.LOW], SeverityLevel.LOW),
        ],
        ids=[
            "low+high", "high+low", "info+critical", "critical+info",
            "medium+low", "low+medium", "high+critical", "info+low",
        ],
    )
    def test_pair_highest_wins(
        self, levels: list[SeverityLevel], expected: SeverityLevel,
    ) -> None:
        assert merge_severities(levels) is expected

    @pytest.mark.parametrize("level", list(SeverityLevel), ids=lambda s: s.name)
    def test_all_same_returns_that_level(self, level: SeverityLevel) -> None:
        assert merge_severities([level, level, level]) is level

    def test_mixed_all_five(self) -> None:
        result = merge_severities([
            SeverityLevel.INFO,
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.HIGH,
            SeverityLevel.CRITICAL,
        ])
        assert result is SeverityLevel.CRITICAL

    def test_mixed_all_five_reversed(self) -> None:
        result = merge_severities([
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        ])
        assert result is SeverityLevel.CRITICAL

    def test_multiple_duplicates_highest_wins(self) -> None:
        result = merge_severities([
            SeverityLevel.LOW,
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
        ])
        assert result is SeverityLevel.MEDIUM

    def test_ordering_critical_highest(self) -> None:
        """Verify CRITICAL beats everything."""
        for other in [SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            assert merge_severities([other, SeverityLevel.CRITICAL]) is SeverityLevel.CRITICAL

    def test_ordering_info_lowest(self) -> None:
        """INFO loses to everything except itself."""
        for other in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            assert merge_severities([SeverityLevel.INFO, other]) is other

    def test_large_list_all_info_except_one_high(self) -> None:
        levels = [SeverityLevel.INFO] * 100 + [SeverityLevel.HIGH]
        assert merge_severities(levels) is SeverityLevel.HIGH

    def test_large_list_all_same(self) -> None:
        levels = [SeverityLevel.MEDIUM] * 50
        assert merge_severities(levels) is SeverityLevel.MEDIUM

    def test_adjacent_severities(self) -> None:
        """Test pairs of adjacent severity levels."""
        assert merge_severities([SeverityLevel.INFO, SeverityLevel.LOW]) is SeverityLevel.LOW
        assert merge_severities([SeverityLevel.LOW, SeverityLevel.MEDIUM]) is SeverityLevel.MEDIUM
        assert merge_severities([SeverityLevel.MEDIUM, SeverityLevel.HIGH]) is SeverityLevel.HIGH
        assert merge_severities([SeverityLevel.HIGH, SeverityLevel.CRITICAL]) is SeverityLevel.CRITICAL
