"""SARIF rule index building and tool name extraction."""

from __future__ import annotations

from typing import Any


def build_rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build a lookup dict from rule ID to rule metadata.

    Indexes rules from both ``tool.driver.rules`` and
    ``tool.extensions[].rules`` so that extension-defined rules (e.g.
    CodeQL query packs) are resolved correctly.  Driver rules take
    precedence when IDs collide.
    """
    index: dict[str, dict[str, Any]] = {}
    tool = run.get("tool")
    if not isinstance(tool, dict):
        return index

    # Index extension rules first so driver rules can override.
    extensions = tool.get("extensions")
    if isinstance(extensions, list):
        for ext in extensions:
            if not isinstance(ext, dict):
                continue
            ext_rules = ext.get("rules")
            if not isinstance(ext_rules, list):
                continue
            for rule in ext_rules:
                if isinstance(rule, dict):
                    rule_id = rule.get("id", "")
                    if rule_id:
                        index[str(rule_id)] = rule

    # Driver rules override extensions on ID collision.
    driver = tool.get("driver")
    if isinstance(driver, dict):
        rules = driver.get("rules")
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict):
                    rule_id = rule.get("id", "")
                    if rule_id:
                        index[str(rule_id)] = rule

    return index


def extract_tool_name(run: dict[str, Any], *, fallback: str) -> str:
    """Extract tool name from SARIF run object."""
    tool = run.get("tool")
    if isinstance(tool, dict):
        driver = tool.get("driver")
        if isinstance(driver, dict):
            name = driver.get("name", "")
            if name:
                return str(name).strip()
    return fallback
