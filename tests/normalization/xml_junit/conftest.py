"""Shared fixtures and JUnit XML builders for xml_junit parser tests."""

from __future__ import annotations

from typing import Any

import pytest

from nocturna_engine.normalization.parsers.base import ParserConfig
from nocturna_engine.normalization.parsers.xml_junit import JunitXmlParser
from nocturna_engine.normalization.severity import build_severity_map


# ---------------------------------------------------------------------------
# Config / parser factory
# ---------------------------------------------------------------------------


def make_config(**kwargs: Any) -> ParserConfig:
    """Build a ParserConfig with sensible defaults for testing."""
    defaults: dict[str, Any] = {
        "tool_name": "test_junit",
        "severity_map": build_severity_map(),
    }
    defaults.update(kwargs)
    return ParserConfig(**defaults)


def make_parser(**kwargs: Any) -> JunitXmlParser:
    """Build a JunitXmlParser with sensible defaults for testing."""
    return JunitXmlParser(make_config(**kwargs))


@pytest.fixture()
def parser() -> JunitXmlParser:
    """Default parser fixture."""
    return make_parser()


# ---------------------------------------------------------------------------
# JUnit XML builders
# ---------------------------------------------------------------------------


def wrap_junit(
    suites_xml: str,
    *,
    xml_declaration: bool = True,
) -> str:
    """Build a complete JUnit XML document with <testsuites> root."""
    decl = '<?xml version="1.0" encoding="UTF-8"?>\n' if xml_declaration else ""
    return f"{decl}<testsuites>\n{suites_xml}\n</testsuites>"


def wrap_junit_single_suite(
    cases_xml: str,
    *,
    suite_name: str = "Security Scan",
    tests: int | None = None,
    failures: int | None = None,
    xml_declaration: bool = True,
) -> str:
    """Build a JUnit XML document with a single <testsuite>."""
    suite = junit_testsuite(
        cases_xml,
        name=suite_name,
        tests=tests,
        failures=failures,
    )
    return wrap_junit(suite, xml_declaration=xml_declaration)


def junit_testsuite(
    cases_xml: str,
    *,
    name: str = "Security Scan",
    tests: int | None = None,
    failures: int | None = None,
) -> str:
    """Build a <testsuite> element."""
    attrs = f'name="{name}"'
    if tests is not None:
        attrs += f' tests="{tests}"'
    if failures is not None:
        attrs += f' failures="{failures}"'
    return f"<testsuite {attrs}>\n{cases_xml}\n</testsuite>"


def junit_testcase(
    *,
    classname: str = "test.Class",
    name: str = "test_method",
    children_xml: str = "",
) -> str:
    """Build a <testcase> element."""
    if children_xml:
        return (
            f'<testcase classname="{classname}" name="{name}">'
            f"{children_xml}"
            "</testcase>"
        )
    return f'<testcase classname="{classname}" name="{name}"/>'


def junit_failure(
    text: str = "",
    *,
    message: str = "",
    failure_type: str = "",
) -> str:
    """Build a <failure> element."""
    attrs = ""
    if message:
        attrs += f' message="{message}"'
    if failure_type:
        attrs += f' type="{failure_type}"'
    return f"<failure{attrs}>{text}</failure>"


def junit_error(
    text: str = "",
    *,
    message: str = "",
    error_type: str = "",
) -> str:
    """Build an <error> element."""
    attrs = ""
    if message:
        attrs += f' message="{message}"'
    if error_type:
        attrs += f' type="{error_type}"'
    return f"<error{attrs}>{text}</error>"


def passed_testcase(
    *,
    classname: str = "safe.Check",
    name: str = "passed_check",
) -> str:
    """Build a passing <testcase> (no failure/error child)."""
    return junit_testcase(classname=classname, name=name)


# ---------------------------------------------------------------------------
# Realistic tool-specific builders
# ---------------------------------------------------------------------------


def trivy_testcase(
    cve: str,
    package: str,
    severity: str,
    *,
    fixed_version: str = "",
    installed_version: str = "",
) -> str:
    """Build a Trivy-style testcase."""
    body_lines = [f"Package: {package}"]
    if installed_version:
        body_lines.append(f"Installed Version: {installed_version}")
    if fixed_version:
        body_lines.append(f"Fixed Version: {fixed_version}")
    body_lines.append(f"CVE: {cve}")
    body = "\n".join(body_lines)
    return junit_testcase(
        classname=f"trivy.{severity.upper()}",
        name=f"{cve}: {package} vulnerability",
        children_xml=junit_failure(
            body,
            message=f"{severity.upper()} vulnerability",
            failure_type="vulnerability",
        ),
    )


def checkov_testcase(
    check_id: str,
    check_name: str,
    resource: str,
    file_path: str,
    *,
    line: int = 1,
) -> str:
    """Build a Checkov-style testcase."""
    body = f"Resource: {resource}\nFile: {file_path}:{line}"
    return junit_testcase(
        classname=f"checkov.{check_id}",
        name=check_name,
        children_xml=junit_failure(
            body,
            message="Check failed",
            failure_type="policy_violation",
        ),
    )


def bandit_testcase(
    issue_id: str,
    description: str,
    severity: str,
    file_path: str,
    *,
    line: int = 1,
    cwe: str = "",
) -> str:
    """Build a Bandit-style testcase."""
    body = f"File: {file_path}:{line}\nSeverity: {severity.upper()}"
    if cwe:
        body += f"\n{cwe}"
    return junit_testcase(
        classname=f"bandit.{issue_id}",
        name=description,
        children_xml=junit_failure(
            body,
            message=f"{severity.upper()} severity issue",
            failure_type="security",
        ),
    )
