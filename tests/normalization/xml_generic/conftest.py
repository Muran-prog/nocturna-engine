"""Shared fixtures and XML builders for xml_generic parser tests."""

from __future__ import annotations

from typing import Any

import pytest

from nocturna_engine.normalization.parsers.base import ParserConfig
from nocturna_engine.normalization.parsers.xml_generic import GenericXmlParser
from nocturna_engine.normalization.severity import build_severity_map


# ---------------------------------------------------------------------------
# Config / parser factory
# ---------------------------------------------------------------------------


def make_config(**kwargs: Any) -> ParserConfig:
    """Build a ParserConfig with sensible defaults for testing."""
    defaults: dict[str, Any] = {
        "tool_name": "test_tool",
        "severity_map": build_severity_map(),
    }
    defaults.update(kwargs)
    return ParserConfig(**defaults)


def make_parser(**kwargs: Any) -> GenericXmlParser:
    """Build a GenericXmlParser with sensible defaults for testing."""
    return GenericXmlParser(make_config(**kwargs))


@pytest.fixture()
def parser() -> GenericXmlParser:
    """Default parser fixture."""
    return make_parser()


# ---------------------------------------------------------------------------
# Nessus XML builders
# ---------------------------------------------------------------------------


def wrap_nessus(
    hosts_xml: str,
    *,
    policy: str = "",
) -> str:
    """Build a complete Nessus XML document."""
    policy_block = f"<Policy>{policy}</Policy>" if policy else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<NessusClientData_v2>\n"
        f"{policy_block}"
        f"<Report name=\"test_scan\">\n{hosts_xml}\n</Report>\n"
        "</NessusClientData_v2>"
    )


def nessus_host(
    name: str = "192.168.1.1",
    items_xml: str = "",
) -> str:
    """Build a Nessus ReportHost element."""
    return (
        f'<ReportHost name="{name}">\n'
        f"{items_xml}\n"
        "</ReportHost>"
    )


def nessus_item(
    plugin_name: str = "Test Plugin",
    plugin_id: str = "12345",
    severity: str = "2",
    port: str = "443",
    protocol: str = "tcp",
    svc_name: str = "https",
    children_xml: str = "",
) -> str:
    """Build a Nessus ReportItem element."""
    return (
        f'<ReportItem pluginName="{plugin_name}" pluginID="{plugin_id}" '
        f'severity="{severity}" port="{port}" protocol="{protocol}" '
        f'svc_name="{svc_name}">\n'
        f"{children_xml}\n"
        "</ReportItem>"
    )


def nessus_child(tag: str, text: str) -> str:
    """Build a child element for a Nessus ReportItem."""
    return f"<{tag}>{text}</{tag}>"


# ---------------------------------------------------------------------------
# OpenVAS XML builders
# ---------------------------------------------------------------------------


def wrap_openvas(results_xml: str) -> str:
    """Build a complete OpenVAS XML document."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<report format_id="test">\n'
        f"<results>\n{results_xml}\n</results>\n"
        "</report>"
    )


def openvas_result(
    name: str = "Test Vulnerability",
    host: str = "10.0.0.1",
    port: str = "80/tcp",
    threat: str = "Medium",
    description: str = "A test vulnerability.",
    nvt_xml: str = "",
) -> str:
    """Build an OpenVAS <result> element."""
    return (
        "<result>\n"
        f"<name>{name}</name>\n"
        f"<host>{host}</host>\n"
        f"<port>{port}</port>\n"
        f"<threat>{threat}</threat>\n"
        f"<description>{description}</description>\n"
        f"{nvt_xml}\n"
        "</result>"
    )


def openvas_nvt(
    oid: str = "1.2.3.4.5",
    name: str = "NVT Name",
    cve: str = "",
    cvss_base: str = "",
    solution: str = "",
    tags: str = "",
) -> str:
    """Build an OpenVAS <nvt> element."""
    children = f"<name>{name}</name>\n"
    if cve:
        children += f"<cve>{cve}</cve>\n"
    if cvss_base:
        children += f"<cvss_base>{cvss_base}</cvss_base>\n"
    if solution:
        children += f"<solution>{solution}</solution>\n"
    if tags:
        children += f"<tags>{tags}</tags>\n"
    return f'<nvt oid="{oid}">\n{children}</nvt>'


# ---------------------------------------------------------------------------
# Burp XML builders
# ---------------------------------------------------------------------------


def wrap_burp(issues_xml: str) -> str:
    """Build a complete Burp Suite XML document."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<issues>\n{issues_xml}\n</issues>"
    )


def burp_issue(
    name: str = "SQL Injection",
    host: str = "https://example.com",
    path: str = "/api/login",
    severity: str = "High",
    confidence: str = "Certain",
    issue_detail: str = "Parameter 'id' is vulnerable.",
    remediation_detail: str = "Use parameterized queries.",
    serial_number: str = "1234567890",
    issue_type: str = "16777216",
    host_ip: str = "93.184.216.34",
    issue_background: str = "",
    vuln_classifications: str = "",
) -> str:
    """Build a Burp Suite <issue> element."""
    children = f"<serialNumber>{serial_number}</serialNumber>\n"
    children += f"<type>{issue_type}</type>\n"
    children += f"<name>{name}</name>\n"
    children += f'<host ip="{host_ip}">{host}</host>\n'
    children += f"<path>{path}</path>\n"
    children += f"<severity>{severity}</severity>\n"
    children += f"<confidence>{confidence}</confidence>\n"
    if issue_detail:
        children += f"<issueDetail>{issue_detail}</issueDetail>\n"
    if remediation_detail:
        children += f"<remediationDetail>{remediation_detail}</remediationDetail>\n"
    if issue_background:
        children += f"<issueBackground>{issue_background}</issueBackground>\n"
    if vuln_classifications:
        children += f"<vulnerabilityClassifications>{vuln_classifications}</vulnerabilityClassifications>\n"
    return f"<issue>\n{children}</issue>"


# ---------------------------------------------------------------------------
# Generic XML builder
# ---------------------------------------------------------------------------


def wrap_generic(
    root_tag: str = "scan_results",
    items_xml: str = "",
) -> str:
    """Build a generic XML document with an arbitrary root."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<{root_tag}>\n{items_xml}\n</{root_tag}>"
    )


def generic_vuln(
    tag: str = "vulnerability",
    children: dict[str, str] | None = None,
    attrs: str = "",
) -> str:
    """Build a generic vulnerability-like element."""
    children = children or {}
    attrs_str = f" {attrs}" if attrs else ""
    child_xml = "\n".join(f"<{k}>{v}</{k}>" for k, v in children.items())
    return f"<{tag}{attrs_str}>\n{child_xml}\n</{tag}>"
