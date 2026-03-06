"""HTML parser sub-package — splits HtmlParser into logical modules."""

from nocturna_engine.normalization.parsers.html.parser._core import HtmlParser
from nocturna_engine.normalization.parsers.html.parser._table_conversion import (
    _TableConversionMixin,
)

__all__ = [
    "HtmlParser",
    "_TableConversionMixin",
]
