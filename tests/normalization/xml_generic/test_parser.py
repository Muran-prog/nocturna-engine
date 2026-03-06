"""Integration tests for GenericXmlParser: registration, parse/stream, errors, XXE."""

from __future__ import annotations

import pytest

from nocturna_engine.models.finding import SeverityLevel
from nocturna_engine.normalization.parsers.xml_generic import GenericXmlParser
from nocturna_engine.normalization.registry import get_global_registry
from tests.normalization.xml_generic.conftest import (
    burp_issue,
    make_parser,
    nessus_child,
    nessus_host,
    nessus_item,
    openvas_result,
    wrap_burp,
    wrap_nessus,
    wrap_openvas,
)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_parser_registered_in_global_registry(self) -> None:
        registry = get_global_registry()
        parsers = registry.list_parsers()
        names = [p["name"] for p in parsers]
        assert "xml_generic" in names

    def test_parser_class_is_correct(self) -> None:
        registry = get_global_registry()
        cls = registry.lookup_by_name("xml_generic")
        assert cls is GenericXmlParser

    def test_class_attributes(self) -> None:
        assert GenericXmlParser.parser_name == "xml_generic"
        assert GenericXmlParser.source_format == "xml"


# ---------------------------------------------------------------------------
# parse() — batch mode
# ---------------------------------------------------------------------------


class TestParseBatch:
    async def test_nessus_batch(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item(severity="3")))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) >= 1
        assert result.findings[0].severity == SeverityLevel.HIGH

    async def test_openvas_batch(self) -> None:
        xml = wrap_openvas(openvas_result(threat="Medium"))
        result = await make_parser(tool_name="openvas").parse(xml)
        assert len(result.findings) >= 1

    async def test_burp_batch(self) -> None:
        xml = wrap_burp(burp_issue(severity="High"))
        result = await make_parser(tool_name="burp").parse(xml)
        assert len(result.findings) >= 1

    async def test_str_input(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.findings) >= 1

    async def test_bytes_input(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml.encode("utf-8"))
        assert len(result.findings) >= 1


# ---------------------------------------------------------------------------
# parse_stream() — streaming mode
# ---------------------------------------------------------------------------


class TestParseStream:
    async def test_stream_nessus(self) -> None:
        parser = make_parser(tool_name="nessus")
        xml = wrap_nessus(nessus_host(items_xml=nessus_item())).encode("utf-8")

        async def _stream():
            yield xml

        result = await parser.parse_stream(_stream())
        assert len(result.findings) >= 1

    async def test_stream_chunked(self) -> None:
        parser = make_parser(tool_name="nessus")
        children = nessus_child("description", "Test description for chunking")
        xml = wrap_nessus(
            nessus_host(items_xml=nessus_item(severity="2", children_xml=children)),
        ).encode("utf-8")

        chunk_size = 64
        chunks = [xml[i : i + chunk_size] for i in range(0, len(xml), chunk_size)]

        async def _stream():
            for c in chunks:
                yield c

        result = await parser.parse_stream(_stream())
        assert len(result.findings) >= 1

    async def test_stream_openvas(self) -> None:
        parser = make_parser(tool_name="openvas")
        xml = wrap_openvas(openvas_result(threat="High")).encode("utf-8")

        async def _stream():
            yield xml

        result = await parser.parse_stream(_stream())
        assert len(result.findings) >= 1

    async def test_stream_burp(self) -> None:
        parser = make_parser(tool_name="burp")
        xml = wrap_burp(burp_issue(severity="Medium")).encode("utf-8")

        async def _stream():
            yield xml

        result = await parser.parse_stream(_stream())
        assert len(result.findings) >= 1

    async def test_stream_empty(self) -> None:
        parser = make_parser(tool_name="nessus")

        async def _stream():
            return
            yield  # type: ignore[misc]

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 0

    async def test_stream_malformed(self) -> None:
        parser = make_parser(tool_name="nessus")

        async def _stream():
            yield b"<not valid xml<<<>>>"

        result = await parser.parse_stream(_stream())
        assert len(result.issues) >= 1
        assert result.stats.errors_encountered >= 1


# ---------------------------------------------------------------------------
# Malformed XML
# ---------------------------------------------------------------------------


class TestMalformedXml:
    async def test_invalid_xml_produces_issue(self) -> None:
        result = await make_parser(tool_name="nessus").parse("<broken xml<<<>>>")
        assert len(result.issues) >= 1
        assert result.stats.errors_encountered >= 1
        assert "XML parse error" in result.issues[0].message

    async def test_truncated_xml(self) -> None:
        xml = '<?xml version="1.0"?><NessusClientData_v2><Report name="x"><ReportHost name="h">'
        result = await make_parser(tool_name="nessus").parse(xml)
        assert len(result.issues) >= 1

    async def test_empty_string(self) -> None:
        result = await make_parser(tool_name="nessus").parse("")
        assert len(result.issues) >= 1

    async def test_empty_bytes(self) -> None:
        result = await make_parser(tool_name="nessus").parse(b"")
        assert len(result.issues) >= 1


# ---------------------------------------------------------------------------
# XXE protection (defusedxml)
# ---------------------------------------------------------------------------


class TestXxeProtection:
    async def test_batch_rejects_entity_expansion(self) -> None:
        """parse() blocks entity expansion via defusedxml."""
        from defusedxml import EntitiesForbidden

        payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE z ['
            '  <!ENTITY a "AAAAAAAAAA">'
            '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            ']>'
            '<NessusClientData_v2><Report name="x">'
            '<ReportHost name="&b;">'
            '<ReportItem pluginName="test" pluginID="1" severity="2" port="80" protocol="tcp">'
            '<description>desc</description>'
            '</ReportItem>'
            '</ReportHost>'
            '</Report></NessusClientData_v2>'
        )
        with pytest.raises(EntitiesForbidden):
            await make_parser(tool_name="nessus").parse(payload)

    async def test_stream_rejects_entity_expansion(self) -> None:
        """parse_stream() blocks entity expansion via defusedxml."""
        from defusedxml import EntitiesForbidden

        payload = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE z ['
            b'  <!ENTITY a "AAAAAAAAAA">'
            b'  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b']>'
            b'<NessusClientData_v2><Report name="x">'
            b'<ReportHost name="&b;"><ReportItem pluginName="t" pluginID="1" severity="2" port="80" protocol="tcp">'
            b'</ReportItem></ReportHost>'
            b'</Report></NessusClientData_v2>'
        )
        parser = make_parser(tool_name="nessus")

        async def _stream():
            yield payload

        with pytest.raises(EntitiesForbidden):
            await parser.parse_stream(_stream())


# ---------------------------------------------------------------------------
# ParseResult structure
# ---------------------------------------------------------------------------


class TestParseResultStructure:
    async def test_result_has_findings_issues_stats(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert hasattr(result, "findings")
        assert hasattr(result, "issues")
        assert hasattr(result, "stats")
        assert isinstance(result.findings, list)
        assert isinstance(result.issues, list)

    async def test_finding_has_fingerprint(self) -> None:
        xml = wrap_nessus(nessus_host(items_xml=nessus_item()))
        result = await make_parser(tool_name="nessus").parse(xml)
        assert result.findings[0].fingerprint
        assert len(result.findings[0].fingerprint) == 64  # SHA-256 hex
