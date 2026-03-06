"""Column alias matching for HTML table headers — delegates to csv_generic aliases."""

from __future__ import annotations

from nocturna_engine.normalization.parsers.csv_generic.column_mapping import (
    _COLUMN_ALIASES,
    _find_column,
)

__all__ = ["_COLUMN_ALIASES", "_find_column"]
