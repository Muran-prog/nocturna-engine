"""Shared constants for AI orchestration mixins."""

from __future__ import annotations

import re
from typing import Any

_WINDOWS_DRIVE_PATTERN = re.compile(r"^[a-zA-Z]:[\\/]")
_WINDOWS_UNC_PATTERN = re.compile(r"^\\\\[^\\/]+[\\/][^\\/]+")

_SAFE_POLICY_PROFILE: dict[str, Any] = {
    "allow_network": False,
    "allow_subprocess": False,
    "allow_filesystem": False,
    "max_timeout_seconds": 20.0,
    "max_output_bytes": 262144,
    "max_retries": 0,
    "circuit_breaker_threshold": 1,
    "quarantine_seconds": 1800.0,
    "strict_quarantine": True,
    "allow_cache": False,
    "egress_allow_hosts": [],
    "egress_deny_hosts": [],
    "egress_allow_cidrs": [],
    "egress_deny_cidrs": [],
    "egress_allow_ports": [],
    "egress_deny_ports": [],
    "egress_allow_protocols": [],
    "egress_deny_protocols": [],
    "default_egress_action": "deny",
}

_FAST_POLICY_PROFILE: dict[str, Any] = {
    "allow_network": True,
    "allow_subprocess": True,
    "allow_filesystem": True,
    "max_timeout_seconds": 120.0,
    "max_output_bytes": 8388608,
    "max_retries": 2,
    "circuit_breaker_threshold": 3,
    "quarantine_seconds": 120.0,
    "strict_quarantine": False,
    "allow_cache": True,
    "egress_allow_hosts": [],
    "egress_deny_hosts": [],
    "egress_allow_cidrs": [],
    "egress_deny_cidrs": [],
    "egress_allow_ports": [],
    "egress_deny_ports": [],
    "egress_allow_protocols": [],
    "egress_deny_protocols": [],
    "default_egress_action": "allow",
}
