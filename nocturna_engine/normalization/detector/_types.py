"""Input format enum, detection result model, and byte-level constants."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class InputFormat(str, Enum):
    """Recognized input format identifiers."""

    SARIF = "sarif"
    JSON = "json"
    JSONL = "jsonl"
    XML_NMAP = "xml_nmap"
    XML_GENERIC = "xml_generic"
    XML_JUNIT = "xml_junit"
    CSV = "csv"
    PLAINTEXT = "plaintext"
    HTML = "html"


# Byte-order marks and magic prefixes for format sniffing.
_UTF8_BOM = b"\xef\xbb\xbf"
_XML_DECLARATION = b"<?xml"
_XML_DECLARATION_UPPER = b"<?XML"

# Maximum bytes to read for format sniffing.
_SNIFF_SIZE = 8192


class DetectionResult(BaseModel):
    """Result of format detection with confidence metadata.

    Attributes:
        format: Detected input format.
        confidence: Detection confidence (0.0-1.0).
        method: How the format was determined.
        tool_hint: Optional detected tool name if identifiable from content.
    """

    model_config = ConfigDict(extra="forbid")

    format: InputFormat
    confidence: float = Field(ge=0.0, le=1.0)
    method: str = Field(min_length=1)
    tool_hint: str | None = Field(default=None)
