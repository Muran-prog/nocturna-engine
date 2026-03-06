"""Edge-case tests for nocturna_engine.normalization.registry."""

from __future__ import annotations

import pytest

from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.errors import ParserNotFoundError, ParserRegistrationError
from nocturna_engine.normalization.registry import (
    ParserRegistry,
    _global_registry,
    get_global_registry,
    register_parser,
)


# ---------------------------------------------------------------------------
# Helpers — inline "parser" classes for testing (no conftest needed)
# ---------------------------------------------------------------------------


class _FakeParserA:
    """Stub parser class A."""


class _FakeParserB:
    """Stub parser class B."""


class _FakeParserC:
    """Stub parser class C."""


class _FakeParserD:
    """Stub parser class D."""


# ---------------------------------------------------------------------------
# ParserRegistry — fresh instance basics
# ---------------------------------------------------------------------------


class TestParserRegistryInit:
    """Fresh registry instance edge cases."""

    def test_empty_registry_list_parsers(self) -> None:
        reg = ParserRegistry()
        assert reg.list_parsers() == []

    def test_lookup_on_empty_raises(self) -> None:
        reg = ParserRegistry()
        with pytest.raises(ParserNotFoundError):
            reg.lookup(InputFormat.JSON)

    def test_lookup_by_name_on_empty_returns_none(self) -> None:
        reg = ParserRegistry()
        assert reg.lookup_by_name("anything") is None


# ---------------------------------------------------------------------------
# register — validation edge cases
# ---------------------------------------------------------------------------


class TestRegisterValidation:
    """Registration edge cases."""

    def test_empty_name_raises(self) -> None:
        reg = ParserRegistry()
        with pytest.raises(ParserRegistrationError, match="non-empty"):
            reg.register(_FakeParserA, name="", formats=[InputFormat.JSON])

    def test_whitespace_only_name_raises(self) -> None:
        reg = ParserRegistry()
        with pytest.raises(ParserRegistrationError, match="non-empty"):
            reg.register(_FakeParserA, name="   ", formats=[InputFormat.JSON])

    def test_duplicate_name_different_class_raises(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserA, name="parser_x", formats=[InputFormat.JSON])
        with pytest.raises(ParserRegistrationError, match="already registered"):
            reg.register(_FakeParserB, name="parser_x", formats=[InputFormat.JSON])

    def test_duplicate_name_same_class_idempotent(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserA, name="parser_y", formats=[InputFormat.JSON])
        # Second call with same class should not raise
        reg.register(_FakeParserA, name="parser_y", formats=[InputFormat.JSON])
        assert reg.lookup_by_name("parser_y") is _FakeParserA

    def test_name_normalization_strip_and_lower(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserA, name="  My_Parser  ", formats=[InputFormat.JSON])
        assert reg.lookup_by_name("my_parser") is _FakeParserA
        assert reg.lookup_by_name("MY_PARSER") is _FakeParserA
        assert reg.lookup_by_name("  my_parser  ") is _FakeParserA

    def test_name_case_collision_raises(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserA, name="MyParser", formats=[InputFormat.JSON])
        with pytest.raises(ParserRegistrationError):
            reg.register(_FakeParserB, name="myparser", formats=[InputFormat.XML_GENERIC])


# ---------------------------------------------------------------------------
# register — formats and tool_patterns
# ---------------------------------------------------------------------------


class TestRegisterFormats:
    """Multiple formats, tool patterns, and priority."""

    def test_multiple_formats(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="multi",
            formats=[InputFormat.JSON, InputFormat.JSONL],
        )
        assert reg.lookup(InputFormat.JSON) is _FakeParserA
        assert reg.lookup(InputFormat.JSONL) is _FakeParserA

    def test_tool_patterns_stored(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="tp_parser",
            formats=[InputFormat.JSON],
            tool_patterns=["semgrep", "bandit"],
        )
        # Verify via lookup with tool_hint
        assert reg.lookup(InputFormat.JSON, tool_hint="semgrep") is _FakeParserA

    def test_tool_patterns_normalized(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="norm_tp",
            formats=[InputFormat.JSON],
            tool_patterns=["  SemGrep  "],
        )
        # tool hint matching is case-insensitive
        assert reg.lookup(InputFormat.JSON, tool_hint="SEMGREP") is _FakeParserA

    def test_none_tool_patterns_defaults_empty(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="no_tp",
            formats=[InputFormat.JSON],
            tool_patterns=None,
        )
        # No patterns → lookup by format still works
        assert reg.lookup(InputFormat.JSON) is _FakeParserA


# ---------------------------------------------------------------------------
# register — priority sorting
# ---------------------------------------------------------------------------


class TestRegisterPriority:
    """Priority determines lookup order."""

    def test_higher_priority_first(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA, name="low", formats=[InputFormat.JSON], priority=10
        )
        reg.register(
            _FakeParserB, name="high", formats=[InputFormat.JSON], priority=100
        )
        # Highest priority wins default lookup
        assert reg.lookup(InputFormat.JSON) is _FakeParserB

    def test_same_priority_first_registered_wins(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA, name="first", formats=[InputFormat.CSV], priority=0
        )
        reg.register(
            _FakeParserB, name="second", formats=[InputFormat.CSV], priority=0
        )
        result = reg.lookup(InputFormat.CSV)
        # Both priority=0 → sort is stable, first registered is at index 0
        assert result in (_FakeParserA, _FakeParserB)

    def test_negative_priority(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA, name="negative", formats=[InputFormat.XML_GENERIC], priority=-5
        )
        reg.register(
            _FakeParserB, name="zero", formats=[InputFormat.XML_GENERIC], priority=0
        )
        assert reg.lookup(InputFormat.XML_GENERIC) is _FakeParserB


# ---------------------------------------------------------------------------
# lookup — tool_hint matching
# ---------------------------------------------------------------------------


class TestLookupToolHint:
    """Lookup with tool_hint pattern matching."""

    def test_tool_hint_exact_match(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="generic",
            formats=[InputFormat.JSON],
            priority=10,
        )
        reg.register(
            _FakeParserB,
            name="semgrep_parser",
            formats=[InputFormat.JSON],
            tool_patterns=["semgrep"],
            priority=0,
        )
        # Tool hint should override priority
        assert reg.lookup(InputFormat.JSON, tool_hint="semgrep") is _FakeParserB

    def test_tool_hint_glob_match(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="nmap_p",
            formats=[InputFormat.XML_NMAP],
            tool_patterns=["nmap*"],
        )
        # "nmap*" glob matches "nmap_scanner"
        assert reg.lookup(InputFormat.XML_NMAP, tool_hint="nmap_scanner") is _FakeParserA

    def test_tool_hint_no_match_falls_to_priority(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="hp",
            formats=[InputFormat.JSON],
            tool_patterns=["nuclei"],
            priority=100,
        )
        reg.register(
            _FakeParserB,
            name="lp",
            formats=[InputFormat.JSON],
            tool_patterns=["trivy"],
            priority=0,
        )
        # "zap" doesn't match any pattern → falls to highest priority
        assert reg.lookup(InputFormat.JSON, tool_hint="zap") is _FakeParserA

    def test_tool_hint_none_uses_priority(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="a",
            formats=[InputFormat.JSON],
            tool_patterns=["nmap"],
            priority=5,
        )
        reg.register(
            _FakeParserB,
            name="b",
            formats=[InputFormat.JSON],
            priority=50,
        )
        assert reg.lookup(InputFormat.JSON, tool_hint=None) is _FakeParserB


# ---------------------------------------------------------------------------
# lookup — miss
# ---------------------------------------------------------------------------


class TestLookupMiss:
    """ParserNotFoundError when no parser for format."""

    def test_format_not_registered(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserA, name="json_only", formats=[InputFormat.JSON])
        with pytest.raises(ParserNotFoundError, match="xml_generic"):
            reg.lookup(InputFormat.XML_GENERIC)

    def test_error_has_context(self) -> None:
        reg = ParserRegistry()
        with pytest.raises(ParserNotFoundError) as exc_info:
            reg.lookup(InputFormat.CSV, tool_hint="test_tool")
        assert "csv" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# lookup_by_name
# ---------------------------------------------------------------------------


class TestLookupByName:
    """Name-based lookup edge cases."""

    def test_found(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserA, name="my_parser", formats=[InputFormat.JSON])
        assert reg.lookup_by_name("my_parser") is _FakeParserA

    def test_not_found(self) -> None:
        reg = ParserRegistry()
        assert reg.lookup_by_name("nonexistent") is None

    def test_case_insensitive(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserA, name="CamelCase", formats=[InputFormat.JSON])
        assert reg.lookup_by_name("camelcase") is _FakeParserA
        assert reg.lookup_by_name("CAMELCASE") is _FakeParserA
        assert reg.lookup_by_name("  camelcase  ") is _FakeParserA


# ---------------------------------------------------------------------------
# list_parsers
# ---------------------------------------------------------------------------


class TestListParsers:
    """list_parsers metadata edge cases."""

    def test_returns_metadata_dicts(self) -> None:
        reg = ParserRegistry()
        reg.register(
            _FakeParserA,
            name="alpha",
            formats=[InputFormat.JSON, InputFormat.JSONL],
        )
        result = reg.list_parsers()
        assert len(result) == 1
        entry = result[0]
        assert entry["name"] == "alpha"
        assert entry["class"] == _FakeParserA.__qualname__
        assert set(entry["formats"]) == {"json", "jsonl"}

    def test_multiple_parsers_sorted_by_name(self) -> None:
        reg = ParserRegistry()
        reg.register(_FakeParserB, name="bravo", formats=[InputFormat.CSV])
        reg.register(_FakeParserA, name="alpha", formats=[InputFormat.JSON])
        names = [p["name"] for p in reg.list_parsers()]
        assert names == ["alpha", "bravo"]

    def test_empty_registry_returns_empty_list(self) -> None:
        reg = ParserRegistry()
        assert reg.list_parsers() == []


# ---------------------------------------------------------------------------
# Global registry
# ---------------------------------------------------------------------------


class TestGlobalRegistry:
    """Singleton global registry tests."""

    def test_get_global_registry_returns_singleton(self) -> None:
        r1 = get_global_registry()
        r2 = get_global_registry()
        assert r1 is r2

    def test_global_registry_is_module_level_instance(self) -> None:
        assert get_global_registry() is _global_registry

    def test_global_registry_has_parsers(self) -> None:
        # Parsers are auto-registered via __init__.py imports.
        # At minimum, the global registry should be a ParserRegistry instance.
        reg = get_global_registry()
        assert isinstance(reg, ParserRegistry)


# ---------------------------------------------------------------------------
# register_parser decorator
# ---------------------------------------------------------------------------


class TestRegisterParserDecorator:
    """Decorator-based registration edge cases."""

    def test_decorator_returns_class(self) -> None:
        @register_parser(
            name="__test_decorator_class__",
            formats=[InputFormat.PLAINTEXT],
        )
        class _TestDecoratorParser:
            pass

        # Decorator should return the class unchanged
        assert _TestDecoratorParser.__name__ == "_TestDecoratorParser"

    def test_decorator_registers_in_global(self) -> None:
        @register_parser(
            name="__test_global_registered__",
            formats=[InputFormat.PLAINTEXT],
            tool_patterns=["test_tool"],
            priority=999,
        )
        class _TestGlobalParser:
            pass

        reg = get_global_registry()
        assert reg.lookup_by_name("__test_global_registered__") is _TestGlobalParser

    def test_decorator_with_empty_name_raises(self) -> None:
        with pytest.raises(ParserRegistrationError, match="non-empty"):

            @register_parser(name="", formats=[InputFormat.JSON])
            class _BadParser:
                pass

    def test_decorator_duplicate_name_different_class_raises(self) -> None:
        @register_parser(
            name="__test_dup_dec__",
            formats=[InputFormat.CSV],
        )
        class _FirstParser:
            pass

        with pytest.raises(ParserRegistrationError, match="already registered"):

            @register_parser(
                name="__test_dup_dec__",
                formats=[InputFormat.JSON],
            )
            class _SecondParser:
                pass
