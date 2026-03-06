"""DSL parsing helpers for AI-first planning API."""

from __future__ import annotations

import shlex


def parse_ai_dsl(dsl: str) -> dict[str, str]:
    """Parse simple key=value DSL used by AI-first API."""

    payload: dict[str, str] = {}
    for token in shlex.split(dsl):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        payload[key.strip().lower()] = value.strip()
    return payload
