"""JUnit XML parser for security tool output (Trivy, Checkov, Bandit, Safety, Snyk, ZAP).

Parses JUnit XML ``<testcase>`` elements with ``<failure>`` or ``<error>``
children into normalized :class:`Finding` objects. Passed test cases (no
failure/error child) are silently skipped.

Uses SAX-based streaming via :mod:`defusedxml` for XXE-safe parsing.
"""

from nocturna_engine.normalization.parsers.xml_junit._constants import (
    _FILE_PATH_RE,
    _RESOURCE_RE,
    _SEVERITY_RE,
    _URL_RE,
)
from nocturna_engine.normalization.parsers.xml_junit._helpers import (
    _extract_cves,
    _extract_cwes,
    _extract_severity_token,
    _extract_target,
)
from nocturna_engine.normalization.parsers.xml_junit._sax_handler import (
    _JunitSaxHandler,
)
from nocturna_engine.normalization.parsers.xml_junit.parser import JunitXmlParser

__all__ = [
    "JunitXmlParser",
    "_FILE_PATH_RE",
    "_JunitSaxHandler",
    "_RESOURCE_RE",
    "_SEVERITY_RE",
    "_URL_RE",
    "_extract_cves",
    "_extract_cwes",
    "_extract_severity_token",
    "_extract_target",
]
