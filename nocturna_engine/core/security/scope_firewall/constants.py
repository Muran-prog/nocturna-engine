"""Scope firewall constants and internal validation patterns."""

from __future__ import annotations

import re

SCOPE_REASON_DENIED = "scope_denied"
SCOPE_REASON_KILL_SWITCH = "scope_kill_switch"
SCOPE_REASON_INVALID_TARGET = "scope_invalid_target"

_RULE_KEYS = {
    "allowlist_hosts",
    "allowlist_cidrs",
    "denylist_hosts",
    "denylist_cidrs",
    "kill_switch",
}
_LABEL_PATTERN = re.compile(r"^[a-z0-9-]{1,63}$")

