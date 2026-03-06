"""Constants for subprocess-based tool integrations."""

from __future__ import annotations

import re

DEFAULT_MAX_OUTPUT_SIZE_BYTES = 50 * 1024 * 1024
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
