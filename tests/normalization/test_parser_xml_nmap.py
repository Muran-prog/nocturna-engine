"""Edge-case focused tests for nocturna_engine.normalization.parsers.xml_nmap."""

from __future__ import annotations

from typing import Any

import pytest

from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.normalization.parsers.base import ParseResult, ParserConfig
from nocturna_engine.normalization.parsers.xml_nmap import (
    NmapXmlParser,
    _HIGH_RISK_PORTS,
    _MEDIUM_RISK_PORTS,
    _NmapSaxHandler,
    _extract_cve_from_text,
    _port_severity,
)
from nocturna_engine.normalization.severity import build_severity_map


def _make_config(**kwargs: Any) -> ParserConfig:
    defaults: dict[str, Any] = {
        "tool_name": "nmap",
        "severity_map": build_severity_map(),
    }
    defaults.update(kwargs)
    return ParserConfig(**defaults)


def _parser(**kwargs: Any) -> NmapXmlParser:
    return NmapXmlParser(_make_config(**kwargs))


def _wrap_nmap_xml(hosts_xml: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<nmaprun scanner="nmap" start="1700000000">\n'
        f"{hosts_xml}\n"
        "</nmaprun>"
    )


def _host_xml(
    addr: str = "192.168.1.1",
    addr_type: str = "ipv4",
    host_state: str = "up",
    ports_xml: str = "",
    hostname: str = "",
) -> str:
    hostname_el = f'<hostname name="{hostname}"/>' if hostname else ""
    return (
        "<host>"
        f'<status state="{host_state}"/>'
        f'<address addr="{addr}" addrtype="{addr_type}"/>'
        f"{hostname_el}"
        f"<ports>{ports_xml}</ports>"
        "</host>"
    )


def _port_xml(
    portid: str = "80",
    protocol: str = "tcp",
    state: str = "open",
    service_name: str = "",
    product: str = "",
    version: str = "",
    scripts: list[tuple[str, str]] | None = None,
) -> str:
    service_el = ""
    if service_name or product or version:
        service_el = f'<service name="{service_name}" product="{product}" version="{version}"/>'
    script_els = ""
    if scripts:
        for sid, sout in scripts:
            script_els += f'<script id="{sid}" output="{sout}"/>'
    return (
        f'<port protocol="{protocol}" portid="{portid}">'
        f'<state state="{state}"/>'
        f"{service_el}"
        f"{script_els}"
        "</port>"
    )


# ---------------------------------------------------------------------------
# _port_severity function
# ---------------------------------------------------------------------------


class TestPortSeverity:
    @pytest.mark.parametrize(
        "port",
        sorted(_HIGH_RISK_PORTS),
        ids=[f"high-{p}" for p in sorted(_HIGH_RISK_PORTS)],
    )
    def test_high_risk_ports(self, port: int) -> None:
        assert _port_severity(port, "open") == SeverityLevel.HIGH

    @pytest.mark.parametrize(
        "port",
        sorted(_MEDIUM_RISK_PORTS),
        ids=[f"med-{p}" for p in sorted(_MEDIUM_RISK_PORTS)],
    )
    def test_medium_risk_ports(self, port: int) -> None:
        assert _port_severity(port, "open") == SeverityLevel.MEDIUM

    @pytest.mark.parametrize(
        "port",
        [12345, 9999, 55555, 1],
        ids=["12345", "9999", "55555", "1"],
    )
    def test_other_ports_low(self, port: int) -> None:
        assert _port_severity(port, "open") == SeverityLevel.LOW

    @pytest.mark.parametrize(
        "state",
        ["closed", "filtered", "unfiltered", ""],
        ids=["closed", "filtered", "unfiltered", "empty"],
    )
    def test_non_open_state_is_info(self, state: str) -> None:
        assert _port_severity(445, state) == SeverityLevel.INFO

    def test_open_filtered_not_treated_as_open(self) -> None:
        # _port_severity checks state != "open", so "open|filtered" → INFO
        assert _port_severity(445, "open|filtered") == SeverityLevel.INFO


# ---------------------------------------------------------------------------
# _extract_cve_from_text
# ---------------------------------------------------------------------------


class TestExtractCveFromText:
    def test_found(self) -> None:
        assert _extract_cve_from_text("Found CVE-2024-12345 in output") == "CVE-2024-12345"

    def test_not_found(self) -> None:
        assert _extract_cve_from_text("No CVE here") is None

    def test_case_insensitive(self) -> None:
        assert _extract_cve_from_text("cve-2023-0001 test") == "CVE-2023-0001"

    def test_returns_first(self) -> None:
        result = _extract_cve_from_text("CVE-2024-0001 and CVE-2024-0002")
        assert result == "CVE-2024-0001"

    def test_five_digit_id(self) -> None:
        assert _extract_cve_from_text("CVE-2024-123456") == "CVE-2024-123456"

    def test_empty_string(self) -> None:
        assert _extract_cve_from_text("") is None

    def test_returns_uppercase(self) -> None:
        result = _extract_cve_from_text("cve-2024-99999")
        assert result is not None
        assert result == result.upper()


# ---------------------------------------------------------------------------
# _NmapSaxHandler._is_vuln_script
# ---------------------------------------------------------------------------


class TestIsVulnScript:
    @pytest.mark.parametrize(
        "script_id",
        [
            "vuln-test",
            "vulners",
            "vulscan-scan",
            "exploit-check",
            "cve-2024-0001",
            "ssl-heartbleed",
            "ssl-poodle",
        ],
        ids=["vuln-prefix", "vulners", "vulscan", "exploit", "cve-prefix", "ssl-heartbleed", "ssl-poodle"],
    )
    def test_vuln_scripts_detected(self, script_id: str) -> None:
        assert _NmapSaxHandler._is_vuln_script(script_id) is True

    @pytest.mark.parametrize(
        "script_id",
        [
            "http-title",
            "dns-brute",
            "smb-enum-shares",
            "ftp-anon",
            "banner",
            "http-headers",
        ],
        ids=["http-title", "dns-brute", "smb-enum", "ftp-anon", "banner", "http-headers"],
    )
    def test_non_vuln_scripts_rejected(self, script_id: str) -> None:
        assert _NmapSaxHandler._is_vuln_script(script_id) is False

    def test_case_insensitive(self) -> None:
        assert _NmapSaxHandler._is_vuln_script("VULN-TEST") is True
        assert _NmapSaxHandler._is_vuln_script("SSL-Heartbleed") is True

    def test_empty_string(self) -> None:
        assert _NmapSaxHandler._is_vuln_script("") is False

    def test_contains_match_not_just_prefix(self) -> None:
        # "prefix in lowered" catches "some-vuln-check"
        assert _NmapSaxHandler._is_vuln_script("some-vuln-check") is True


# ---------------------------------------------------------------------------
# Basic parsing: open port → finding
# ---------------------------------------------------------------------------


class TestBasicParsing:
    async def test_single_open_port(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(portid="80", state="open")))
        result = await _parser().parse(xml)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "80" in f.title
        assert f.target == "192.168.1.1"
        assert f.severity == SeverityLevel.MEDIUM  # port 80 is MEDIUM

    async def test_service_detection_in_title_and_evidence(self) -> None:
        port = _port_xml(
            portid="443",
            state="open",
            service_name="https",
            product="nginx",
            version="1.21",
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        f = result.findings[0]
        assert "https" in f.title
        assert f.evidence["service"] == "https"
        assert f.evidence["product"] == "nginx"
        assert f.evidence["version"] == "1.21"

    async def test_bytes_input(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml()))
        result = await _parser().parse(xml.encode("utf-8"))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Port states
# ---------------------------------------------------------------------------


class TestPortStates:
    @pytest.mark.parametrize(
        "state,expected_count",
        [
            ("open", 1),
            ("closed", 0),
            ("filtered", 0),
            ("open|filtered", 1),
            ("unfiltered", 0),
        ],
        ids=["open", "closed", "filtered", "open-filtered", "unfiltered"],
    )
    async def test_port_state_filtering(self, state: str, expected_count: int) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state=state)))
        result = await _parser().parse(xml)
        assert len(result.findings) == expected_count

    async def test_closed_port_skipped_in_stats(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state="closed")))
        result = await _parser().parse(xml)
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# Port severity heuristic via parsing
# ---------------------------------------------------------------------------


class TestPortSeverityViaParsing:
    @pytest.mark.parametrize(
        "port,expected",
        [
            ("22", SeverityLevel.MEDIUM),
            ("445", SeverityLevel.HIGH),
            ("3389", SeverityLevel.HIGH),
            ("12345", SeverityLevel.LOW),
            ("80", SeverityLevel.MEDIUM),
            ("443", SeverityLevel.MEDIUM),
        ],
        ids=["ssh", "smb", "rdp", "random", "http", "https"],
    )
    async def test_severity_heuristic(self, port: str, expected: SeverityLevel) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(portid=port, state="open")))
        result = await _parser().parse(xml)
        assert result.findings[0].severity == expected


# ---------------------------------------------------------------------------
# Empty and minimal scans
# ---------------------------------------------------------------------------


class TestEmptyScans:
    async def test_empty_nmaprun(self) -> None:
        xml = _wrap_nmap_xml("")
        result = await _parser().parse(xml)
        assert len(result.findings) == 0
        assert result.stats.total_records_processed == 0

    async def test_host_no_ports(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=""))
        result = await _parser().parse(xml)
        assert len(result.findings) == 0

    async def test_host_down(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(host_state="down", ports_xml=""))
        result = await _parser().parse(xml)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Malformed XML
# ---------------------------------------------------------------------------


class TestMalformedXml:
    async def test_invalid_xml_produces_issue(self) -> None:
        result = await _parser().parse("<not valid xml<<<>>>")
        assert len(result.issues) >= 1
        assert result.stats.errors_encountered >= 1
        assert "XML parse error" in result.issues[0].message

    async def test_truncated_xml(self) -> None:
        xml = '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        # Truncated — no closing tags
        result = await _parser().parse(xml)
        assert len(result.issues) >= 1

    async def test_empty_string(self) -> None:
        result = await _parser().parse("")
        # Empty input → SAX parse error (no root element)
        assert len(result.issues) >= 1

    async def test_empty_bytes(self) -> None:
        result = await _parser().parse(b"")
        assert len(result.issues) >= 1


# ---------------------------------------------------------------------------
# NSE vuln scripts
# ---------------------------------------------------------------------------


class TestNseVulnScripts:
    async def test_vuln_script_produces_finding(self) -> None:
        port = _port_xml(
            portid="443",
            state="open",
            scripts=[("vuln-cve-2024-0001", "Vulnerable to CVE-2024-0001")],
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        # 1 for open port + 1 for vuln script
        assert len(result.findings) >= 2
        script_findings = [f for f in result.findings if "NSE" in f.title]
        assert len(script_findings) == 1
        assert script_findings[0].severity == SeverityLevel.HIGH  # has CVE

    async def test_non_vuln_script_ignored(self) -> None:
        port = _port_xml(
            portid="80",
            state="open",
            scripts=[("http-title", "Welcome to nginx")],
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        # Only 1 for open port, script should be ignored
        assert len(result.findings) == 1
        assert "NSE" not in result.findings[0].title

    async def test_vuln_script_cve_extraction(self) -> None:
        port = _port_xml(
            portid="443",
            state="open",
            scripts=[("ssl-heartbleed", "CVE-2014-0160 is present")],
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        script_findings = [f for f in result.findings if "NSE" in f.title]
        assert len(script_findings) == 1
        assert script_findings[0].severity == SeverityLevel.HIGH

    async def test_vuln_script_no_cve_medium_severity(self) -> None:
        port = _port_xml(
            portid="80",
            state="open",
            scripts=[("vuln-generic", "Some vulnerability found")],
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        script_findings = [f for f in result.findings if "NSE" in f.title]
        assert len(script_findings) == 1
        assert script_findings[0].severity == SeverityLevel.MEDIUM

    async def test_vuln_script_empty_output_skipped(self) -> None:
        port = _port_xml(
            portid="80",
            state="open",
            scripts=[("vuln-test", "")],
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        script_findings = [f for f in result.findings if "NSE" in f.title]
        assert len(script_findings) == 0


# ---------------------------------------------------------------------------
# IPv6 and hostname
# ---------------------------------------------------------------------------


class TestAddressing:
    async def test_ipv6_address(self) -> None:
        xml = _wrap_nmap_xml(
            _host_xml(
                addr="fe80::1",
                addr_type="ipv6",
                ports_xml=_port_xml(state="open"),
            )
        )
        result = await _parser().parse(xml)
        assert result.findings[0].target == "fe80::1"

    async def test_hostname_used_when_no_address_first(self) -> None:
        # Build host manually with hostname before address
        host = (
            "<host>"
            '<status state="up"/>'
            '<hostname name="server.local"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            "<ports>"
            + _port_xml(state="open")
            + "</ports></host>"
        )
        xml = _wrap_nmap_xml(host)
        result = await _parser().parse(xml)
        # hostname comes first, sets _current_host
        assert result.findings[0].target == "server.local"

    async def test_target_hint_fallback(self) -> None:
        # No address or hostname in host
        host = (
            "<host>"
            '<status state="up"/>'
            "<ports>"
            + _port_xml(state="open")
            + "</ports></host>"
        )
        xml = _wrap_nmap_xml(host)
        result = await _parser(target_hint="fallback.com").parse(xml)
        assert result.findings[0].target == "fallback.com"

    async def test_no_target_no_hint(self) -> None:
        host = (
            "<host>"
            '<status state="up"/>'
            "<ports>"
            + _port_xml(state="open")
            + "</ports></host>"
        )
        xml = _wrap_nmap_xml(host)
        result = await _parser().parse(xml)
        assert result.findings[0].target == "unknown"


# ---------------------------------------------------------------------------
# Multiple hosts and ports
# ---------------------------------------------------------------------------


class TestMultipleHostsPorts:
    async def test_two_hosts_two_ports_each(self) -> None:
        ports1 = _port_xml(portid="22", state="open") + _port_xml(portid="80", state="open")
        ports2 = _port_xml(portid="443", state="open") + _port_xml(portid="8080", state="open")
        hosts = _host_xml(addr="10.0.0.1", ports_xml=ports1) + _host_xml(
            addr="10.0.0.2", ports_xml=ports2
        )
        xml = _wrap_nmap_xml(hosts)
        result = await _parser().parse(xml)
        assert len(result.findings) == 4
        targets = {f.target for f in result.findings}
        assert targets == {"10.0.0.1", "10.0.0.2"}

    async def test_mixed_open_and_closed(self) -> None:
        ports = (
            _port_xml(portid="22", state="open")
            + _port_xml(portid="23", state="closed")
            + _port_xml(portid="80", state="open")
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=ports))
        result = await _parser().parse(xml)
        assert len(result.findings) == 2
        assert result.stats.records_skipped == 1


# ---------------------------------------------------------------------------
# preserve_raw
# ---------------------------------------------------------------------------


class TestPreserveRaw:
    async def test_preserve_raw_true(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state="open")))
        result = await _parser(preserve_raw=True).parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta.get("original_record") is not None

    async def test_preserve_raw_false(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state="open")))
        result = await _parser(preserve_raw=False).parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta.get("original_record") is None


# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------


class TestStats:
    async def test_processed_count(self) -> None:
        ports = _port_xml(portid="22", state="open") + _port_xml(portid="80", state="open")
        xml = _wrap_nmap_xml(_host_xml(ports_xml=ports))
        result = await _parser().parse(xml)
        assert result.stats.total_records_processed == 2
        assert result.stats.findings_produced == 2

    async def test_errors_counted_on_malformed(self) -> None:
        result = await _parser().parse("<broken xml")
        assert result.stats.errors_encountered >= 1


# ---------------------------------------------------------------------------
# parse_stream
# ---------------------------------------------------------------------------


class TestParseStream:
    async def test_stream_basic(self) -> None:
        parser = _parser()
        xml = _wrap_nmap_xml(
            _host_xml(ports_xml=_port_xml(state="open"))
        ).encode("utf-8")

        async def _stream():
            yield xml

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 1

    async def test_stream_chunked(self) -> None:
        parser = _parser()
        xml = _wrap_nmap_xml(
            _host_xml(ports_xml=_port_xml(portid="22", state="open"))
        ).encode("utf-8")
        # Split into small chunks
        chunk_size = 50
        chunks = [xml[i : i + chunk_size] for i in range(0, len(xml), chunk_size)]

        async def _stream():
            for c in chunks:
                yield c

        result = await parser.parse_stream(_stream())
        assert len(result.findings) == 1

    async def test_stream_malformed(self) -> None:
        parser = _parser()

        async def _stream():
            yield b"<not valid xml<<<"

        result = await parser.parse_stream(_stream())
        assert len(result.issues) >= 1

    async def test_stream_empty(self) -> None:
        parser = _parser()

        async def _stream():
            return
            yield  # type: ignore[misc]

        result = await parser.parse_stream(_stream())
        # Empty stream → SAX parser may complain about no content
        # At minimum, no findings
        assert len(result.findings) == 0

    async def test_stream_rejects_billion_laughs(self) -> None:
        """parse_stream blocks entity expansion (Billion Laughs) via defusedxml."""
        from defusedxml import EntitiesForbidden

        payload = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE z ['
            b'  <!ENTITY a "AAAAAAAAAA">'
            b'  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            b']>'
            b'<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/>'
            b'<ports><port protocol="tcp" portid="80">'
            b'<state state="open"/>'
            b'<service name="&c;"/>'
            b'</port></ports></host></nmaprun>'
        )

        parser = _parser()

        async def _stream():
            yield payload

        with pytest.raises(EntitiesForbidden):
            await parser.parse_stream(_stream())

# ---------------------------------------------------------------------------
# Description content
# ---------------------------------------------------------------------------


class TestDescriptionContent:
    async def test_description_includes_target_and_state(self) -> None:
        xml = _wrap_nmap_xml(
            _host_xml(
                addr="10.0.0.5",
                ports_xml=_port_xml(portid="22", state="open"),
            )
        )
        result = await _parser().parse(xml)
        desc = result.findings[0].description
        assert "10.0.0.5" in desc
        assert "open" in desc

    async def test_description_includes_service(self) -> None:
        port = _port_xml(portid="22", state="open", service_name="ssh")
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        assert "ssh" in result.findings[0].description.lower()

    async def test_description_includes_product_version(self) -> None:
        port = _port_xml(
            portid="80",
            state="open",
            service_name="http",
            product="Apache",
            version="2.4.52",
        )
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        desc = result.findings[0].description
        assert "Apache" in desc
        assert "2.4.52" in desc


# ---------------------------------------------------------------------------
# Non-numeric portid edge case
# ---------------------------------------------------------------------------


class TestEdgeCases:
    async def test_non_numeric_portid(self) -> None:
        # portid that can't be parsed as int → defaults to 0
        port = _port_xml(portid="abc", state="open")
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        assert len(result.findings) == 1
        assert result.findings[0].evidence["port"] == 0

    async def test_title_truncated_to_200(self) -> None:
        long_service = "A" * 300
        port = _port_xml(portid="80", state="open", service_name=long_service)
        xml = _wrap_nmap_xml(_host_xml(ports_xml=port))
        result = await _parser().parse(xml)
        assert len(result.findings[0].title) <= 200


# ---------------------------------------------------------------------------
# Origin metadata
# ---------------------------------------------------------------------------


class TestOriginMetadata:
    async def test_origin_parser_name(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state="open")))
        result = await _parser().parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["parser_name"] == "xml_nmap"

    async def test_origin_tool_name(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state="open")))
        result = await _parser(tool_name="custom_nmap").parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["tool_name"] == "custom_nmap"

    async def test_origin_source_format(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state="open")))
        result = await _parser().parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["source_format"] == "xml_nmap"

    async def test_source_reference(self) -> None:
        xml = _wrap_nmap_xml(_host_xml(ports_xml=_port_xml(state="open")))
        result = await _parser(source_reference="scan.xml").parse(xml)
        meta = result.findings[0].metadata["_normalization"]
        assert meta["source_reference"] == "scan.xml"


# ---------------------------------------------------------------------------
# Class attributes
# ---------------------------------------------------------------------------


class TestClassAttributes:
    def test_parser_name(self) -> None:
        assert NmapXmlParser.parser_name == "xml_nmap"

    def test_source_format(self) -> None:
        assert NmapXmlParser.source_format == "xml_nmap"
