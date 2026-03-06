"""Edge-case focused tests for nocturna_engine.normalization.parsers.base."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.metadata import NormalizationOrigin, NormalizationStats
from nocturna_engine.normalization.parsers.base import (
    BaseParser,
    ParseIssue,
    ParseResult,
    ParserConfig,
)
from nocturna_engine.normalization.severity import SeverityMap, build_severity_map


# ---------------------------------------------------------------------------
# Concrete stub subclass for testing BaseParser
# ---------------------------------------------------------------------------


class _StubParser(BaseParser):
    parser_name = "stub"
    source_format = "stub_fmt"

    async def parse(self, data: bytes | str) -> ParseResult:
        return ParseResult()

    async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
        return ParseResult()


# ---------------------------------------------------------------------------
# ParseIssue dataclass
# ---------------------------------------------------------------------------


class TestParseIssue:
    """Edge cases for ParseIssue frozen/slots dataclass."""

    def test_defaults_none(self) -> None:
        issue = ParseIssue(message="boom")
        assert issue.message == "boom"
        assert issue.line_number is None
        assert issue.raw_record is None
        assert issue.error is None

    def test_all_fields_populated(self) -> None:
        err = ValueError("bad")
        issue = ParseIssue(
            message="failed",
            line_number=42,
            raw_record={"col": "val"},
            error=err,
        )
        assert issue.line_number == 42
        assert issue.raw_record == {"col": "val"}
        assert issue.error is err

    def test_frozen_cannot_mutate(self) -> None:
        issue = ParseIssue(message="immutable")
        with pytest.raises(AttributeError):
            issue.message = "changed"  # type: ignore[misc]

    def test_slots_no_dict(self) -> None:
        issue = ParseIssue(message="slots")
        assert not hasattr(issue, "__dict__")

    def test_message_empty_string_allowed(self) -> None:
        issue = ParseIssue(message="")
        assert issue.message == ""

    def test_line_number_zero(self) -> None:
        issue = ParseIssue(message="zero", line_number=0)
        assert issue.line_number == 0

    def test_line_number_negative(self) -> None:
        issue = ParseIssue(message="neg", line_number=-1)
        assert issue.line_number == -1


# ---------------------------------------------------------------------------
# ParseResult dataclass
# ---------------------------------------------------------------------------


class TestParseResult:
    """Edge cases for ParseResult defaults and population."""

    def test_defaults_empty(self) -> None:
        result = ParseResult()
        assert result.findings == []
        assert result.issues == []
        assert isinstance(result.stats, NormalizationStats)
        assert result.stats.total_records_processed == 0

    def test_fresh_stats_each_instance(self) -> None:
        r1 = ParseResult()
        r2 = ParseResult()
        r1.stats.total_records_processed = 99
        assert r2.stats.total_records_processed == 0

    def test_fresh_lists_each_instance(self) -> None:
        r1 = ParseResult()
        r2 = ParseResult()
        r1.findings.append(
            Finding(title="test f", description="desc", tool="t", target="x")
        )
        assert len(r2.findings) == 0

    def test_findings_and_issues_populated(self) -> None:
        f = Finding(title="test f", description="desc", tool="t", target="x")
        issue = ParseIssue(message="warn")
        result = ParseResult(findings=[f], issues=[issue])
        assert len(result.findings) == 1
        assert len(result.issues) == 1

    def test_stats_mutable(self) -> None:
        result = ParseResult()
        result.stats.findings_produced = 5
        assert result.stats.findings_produced == 5


# ---------------------------------------------------------------------------
# ParserConfig
# ---------------------------------------------------------------------------


class TestParserConfig:
    """Edge cases for ParserConfig __slots__ and defaults."""

    def test_required_tool_name(self) -> None:
        cfg = ParserConfig(tool_name="nmap")
        assert cfg.tool_name == "nmap"

    def test_defaults(self) -> None:
        cfg = ParserConfig(tool_name="t")
        assert cfg.target_hint is None
        assert cfg.preserve_raw is True
        assert cfg.source_reference is None
        assert cfg.extra == {}
        assert isinstance(cfg.severity_map, SeverityMap)

    def test_severity_map_none_becomes_default(self) -> None:
        cfg = ParserConfig(tool_name="t", severity_map=None)
        assert isinstance(cfg.severity_map, SeverityMap)

    def test_custom_severity_map(self) -> None:
        smap = build_severity_map(strict=True)
        cfg = ParserConfig(tool_name="t", severity_map=smap)
        assert cfg.severity_map.strict is True

    def test_extra_dict(self) -> None:
        cfg = ParserConfig(tool_name="t", extra={"custom": 123})
        assert cfg.extra["custom"] == 123

    def test_extra_none_becomes_empty(self) -> None:
        cfg = ParserConfig(tool_name="t", extra=None)
        assert cfg.extra == {}

    def test_slots_present(self) -> None:
        assert hasattr(ParserConfig, "__slots__")
        assert "tool_name" in ParserConfig.__slots__

    def test_no_instance_dict(self) -> None:
        cfg = ParserConfig(tool_name="t")
        assert not hasattr(cfg, "__dict__")

    def test_all_slots_settable(self) -> None:
        cfg = ParserConfig(
            tool_name="tool",
            target_hint="hint",
            severity_map=SeverityMap(),
            preserve_raw=False,
            source_reference="ref",
            extra={"k": "v"},
        )
        assert cfg.tool_name == "tool"
        assert cfg.target_hint == "hint"
        assert cfg.preserve_raw is False
        assert cfg.source_reference == "ref"

    def test_keyword_only_construction(self) -> None:
        with pytest.raises(TypeError):
            ParserConfig("nmap")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# BaseParser abstract
# ---------------------------------------------------------------------------


class TestBaseParserAbstract:
    """Ensure BaseParser cannot be instantiated and requires subclass impl."""

    def test_cannot_instantiate_directly(self) -> None:
        cfg = ParserConfig(tool_name="t")
        with pytest.raises(TypeError):
            BaseParser(cfg)  # type: ignore[abstract]

    def test_subclass_missing_parse_raises(self) -> None:
        with pytest.raises(TypeError):

            class _Bad(BaseParser):
                async def parse_stream(self, stream: AsyncIterator[bytes]) -> ParseResult:
                    return ParseResult()

            _Bad(ParserConfig(tool_name="t"))  # type: ignore[abstract]

    def test_subclass_missing_parse_stream_raises(self) -> None:
        with pytest.raises(TypeError):

            class _Bad(BaseParser):
                async def parse(self, data: bytes | str) -> ParseResult:
                    return ParseResult()

            _Bad(ParserConfig(tool_name="t"))  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# BaseParser concrete subclass lifecycle
# ---------------------------------------------------------------------------


class TestBaseParserConcrete:
    """Test BaseParser via concrete _StubParser."""

    def test_config_property(self) -> None:
        cfg = ParserConfig(tool_name="my_tool")
        parser = _StubParser(cfg)
        assert parser.config is cfg

    def test_logger_injected(self) -> None:
        import structlog

        log = structlog.get_logger("custom")
        cfg = ParserConfig(tool_name="t")
        parser = _StubParser(cfg, logger=log)
        assert parser.logger is log

    def test_logger_default_created(self) -> None:
        cfg = ParserConfig(tool_name="t")
        parser = _StubParser(cfg)
        assert parser.logger is not None

    def test_parser_name_and_source_format(self) -> None:
        cfg = ParserConfig(tool_name="t")
        parser = _StubParser(cfg)
        assert parser.parser_name == "stub"
        assert parser.source_format == "stub_fmt"

    async def test_parse_returns_empty(self) -> None:
        parser = _StubParser(ParserConfig(tool_name="t"))
        result = await parser.parse("data")
        assert result.findings == []


# ---------------------------------------------------------------------------
# _build_origin
# ---------------------------------------------------------------------------


class TestBuildOrigin:
    """Edge cases for BaseParser._build_origin."""

    def test_minimal_origin(self) -> None:
        cfg = ParserConfig(tool_name="nmap")
        parser = _StubParser(cfg)
        origin = parser._build_origin()
        assert origin.parser_name == "stub"
        assert origin.tool_name == "nmap"
        assert origin.source_format == "stub_fmt"
        assert origin.source_reference is None
        assert origin.original_severity is None
        assert origin.original_record is None
        assert origin.line_number is None

    def test_with_all_fields(self) -> None:
        cfg = ParserConfig(tool_name="nmap", source_reference="file.xml", preserve_raw=True)
        parser = _StubParser(cfg)
        origin = parser._build_origin(
            original_severity="high",
            original_record={"port": 80},
            line_number=10,
        )
        assert origin.original_severity == "high"
        assert origin.original_record == {"port": 80}
        assert origin.line_number == 10
        assert origin.source_reference == "file.xml"

    def test_preserve_raw_false_drops_record(self) -> None:
        cfg = ParserConfig(tool_name="t", preserve_raw=False)
        parser = _StubParser(cfg)
        origin = parser._build_origin(original_record={"data": "secret"})
        assert origin.original_record is None

    def test_preserve_raw_true_keeps_record(self) -> None:
        cfg = ParserConfig(tool_name="t", preserve_raw=True)
        parser = _StubParser(cfg)
        origin = parser._build_origin(original_record={"data": "keep"})
        assert origin.original_record == {"data": "keep"}

    def test_origin_has_normalized_at(self) -> None:
        cfg = ParserConfig(tool_name="t")
        parser = _StubParser(cfg)
        origin = parser._build_origin()
        assert origin.normalized_at is not None


# ---------------------------------------------------------------------------
# _attach_origin
# ---------------------------------------------------------------------------


class TestAttachOrigin:
    """Edge cases for BaseParser._attach_origin."""

    def test_returns_new_finding_with_normalization(self) -> None:
        cfg = ParserConfig(tool_name="t")
        parser = _StubParser(cfg)
        finding = Finding(title="test title", description="desc", tool="t", target="x")
        origin = parser._build_origin()
        result = parser._attach_origin(finding, origin)
        assert result is not finding
        assert "_normalization" in result.metadata
        assert result.metadata["_normalization"]["parser_name"] == "stub"

    def test_preserves_existing_metadata(self) -> None:
        cfg = ParserConfig(tool_name="t")
        parser = _StubParser(cfg)
        finding = Finding(
            title="test title",
            description="desc",
            tool="t",
            target="x",
            metadata={"custom_key": "value"},
        )
        origin = parser._build_origin()
        result = parser._attach_origin(finding, origin)
        assert result.metadata["custom_key"] == "value"
        assert "_normalization" in result.metadata

    def test_does_not_mutate_original(self) -> None:
        cfg = ParserConfig(tool_name="t")
        parser = _StubParser(cfg)
        finding = Finding(title="test title", description="desc", tool="t", target="x")
        origin = parser._build_origin()
        parser._attach_origin(finding, origin)
        assert "_normalization" not in finding.metadata


# ---------------------------------------------------------------------------
# _make_issue
# ---------------------------------------------------------------------------


class TestMakeIssue:
    """Edge cases for BaseParser._make_issue."""

    def test_basic_issue(self) -> None:
        parser = _StubParser(ParserConfig(tool_name="t"))
        issue = parser._make_issue("something went wrong")
        assert issue.message == "something went wrong"
        assert issue.line_number is None

    def test_with_line_number(self) -> None:
        parser = _StubParser(ParserConfig(tool_name="t"))
        issue = parser._make_issue("err", line_number=5)
        assert issue.line_number == 5

    def test_with_raw_record(self) -> None:
        parser = _StubParser(ParserConfig(tool_name="t"))
        issue = parser._make_issue("err", raw_record={"a": 1})
        assert issue.raw_record == {"a": 1}

    def test_with_error(self) -> None:
        parser = _StubParser(ParserConfig(tool_name="t"))
        exc = RuntimeError("bad")
        issue = parser._make_issue("err", error=exc)
        assert issue.error is exc

    def test_all_params(self) -> None:
        parser = _StubParser(ParserConfig(tool_name="t"))
        exc = TypeError("type")
        issue = parser._make_issue(
            "full issue",
            line_number=99,
            raw_record={"key": "val"},
            error=exc,
        )
        assert issue.message == "full issue"
        assert issue.line_number == 99
        assert issue.raw_record == {"key": "val"}
        assert issue.error is exc

    def test_returns_frozen_issue(self) -> None:
        parser = _StubParser(ParserConfig(tool_name="t"))
        issue = parser._make_issue("frozen")
        with pytest.raises(AttributeError):
            issue.message = "mutated"  # type: ignore[misc]
