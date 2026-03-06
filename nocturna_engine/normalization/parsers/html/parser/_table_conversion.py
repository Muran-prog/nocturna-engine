"""Table → Finding conversion mixin for the HTML parser."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nocturna_engine.models.finding import Finding
from nocturna_engine.normalization.parsers.html._table_extractor import (
    _COLUMN_ALIASES,
    _ExtractedTable,
    _find_column,
)

if TYPE_CHECKING:
    from nocturna_engine.normalization.metadata import NormalizationStats


class _TableConversionMixin:
    """Mixin providing table-to-Finding conversion for :class:`HtmlParser`.

    All methods assume they run on an ``HtmlParser`` instance that inherits
    from ``BaseParser`` (providing ``_config``, ``_build_origin``,
    ``_attach_origin``, ``_make_issue``).
    """

    # ------------------------------------------------------------------
    # Table → Finding conversion
    # ------------------------------------------------------------------

    def _extract_from_table(
        self,
        table: _ExtractedTable,
        *,
        table_index: int,
        stats: NormalizationStats,
    ) -> tuple[list[Finding], list[Any]]:
        """Convert an extracted HTML table into findings.

        Args:
            table: Extracted table with headers and rows.
            table_index: 0-based table index in the document.
            stats: Stats accumulator to update.

        Returns:
            tuple: (findings, issues).
        """
        column_map = self._build_column_map(table.headers)
        findings: list[Finding] = []
        issues = []

        for row_index, row in enumerate(table.rows):
            stats.total_records_processed += 1
            if not any(cell.strip() for cell in row):
                stats.records_skipped += 1
                continue

            try:
                finding = self._row_to_finding(
                    row,
                    column_map=column_map,
                    table_index=table_index,
                    row_index=row_index,
                )
                if finding is not None:
                    findings.append(finding)
                    stats.findings_produced += 1
                else:
                    stats.records_skipped += 1
            except (RecursionError, MemoryError):
                raise
            except Exception as exc:
                stats.errors_encountered += 1
                issues.append(self._make_issue(
                    f"Failed to convert HTML table[{table_index}] row {row_index}: {exc}",
                    error=exc,
                ))

        return findings, issues

    def _build_column_map(self, headers: list[str]) -> dict[str, int | None]:
        """Build mapping from finding fields to column indices.

        Uses the same alias set as the CSV generic parser.

        Args:
            headers: Lowercased, stripped column headers.

        Returns:
            dict: Field name → column index mapping.
        """
        return {
            field: _find_column(headers, aliases)
            for field, aliases in _COLUMN_ALIASES.items()
        }

    def _row_to_finding(
        self,
        row: list[str],
        *,
        column_map: dict[str, int | None],
        table_index: int,
        row_index: int,
    ) -> Finding | None:
        """Convert one HTML table row to a Finding.

        Args:
            row: Cell values for one table row.
            column_map: Field-to-column-index mapping.
            table_index: 0-based table index in document.
            row_index: 0-based row index in table.

        Returns:
            Finding | None: Normalized finding or None if row lacks title.
        """
        title = self._get_cell(row, column_map.get("title"))
        if not title:
            return None

        description = self._get_cell(row, column_map.get("description")) or title

        raw_severity = self._get_cell(row, column_map.get("severity")) or "info"
        severity = self._config.severity_map.resolve(
            raw_severity,
            tool_name=self._config.tool_name,
        )

        target = self._get_cell(row, column_map.get("target"))
        if not target:
            target = self._config.target_hint or "unknown"

        cwe = self._get_cell(row, column_map.get("cwe")) or None

        cvss: float | None = None
        cvss_str = self._get_cell(row, column_map.get("cvss"))
        if cvss_str:
            try:
                score = float(cvss_str)
                if 0.0 <= score <= 10.0:
                    cvss = score
            except (ValueError, TypeError):
                pass

        tool = self._get_cell(row, column_map.get("tool")) or self._config.tool_name

        evidence: dict[str, Any] = {
            "html_table_index": table_index,
            "html_row_index": row_index,
        }

        origin = self._build_origin(
            original_severity=raw_severity,
            original_record={"cells": row} if self._config.preserve_raw else None,
        )

        finding = Finding(
            title=title[:200],
            description=description,
            severity=severity,
            tool=tool,
            target=target,
            cwe=cwe,
            cvss=cvss,
            evidence=evidence,
        )
        return self._attach_origin(finding, origin)

    @staticmethod
    def _get_cell(row: list[str], index: int | None) -> str:
        """Safely extract a cell value from a table row.

        Args:
            row: Row cell values.
            index: Column index.

        Returns:
            str: Stripped cell value or empty string.
        """
        if index is None or index >= len(row):
            return ""
        return row[index].strip()
