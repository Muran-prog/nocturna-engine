"""SAX-style HTML table extractor using stdlib html.parser."""

from __future__ import annotations

from html.parser import HTMLParser

from nocturna_engine.normalization.parsers.html._constants import (
    _MAX_ROWS_PER_TABLE,
    _MAX_TABLES,
    _MIN_SECURITY_HEADERS,
    _SECURITY_HEADER_KEYWORDS,
)


class _ExtractedTable:
    """Container for a single extracted HTML table.

    Attributes:
        headers: Lowercased, stripped column headers.
        rows: List of row data (each row is a list of cell strings).
    """

    __slots__ = ("headers", "rows")

    def __init__(self, headers: list[str], rows: list[list[str]]) -> None:
        self.headers = headers
        self.rows = rows


class _HtmlTableHandler(HTMLParser):
    """HTMLParser subclass that extracts ``<table>`` structures from HTML.

    Operates in SAX-style: processes tags incrementally without building
    a full DOM tree. Collects tables whose header rows contain
    security-related keywords.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)

        # Collected tables with security-relevant headers.
        self.tables: list[_ExtractedTable] = []

        # All text content extracted (for fallback extraction).
        self.all_text_chunks: list[str] = []

        # --- State tracking ---
        self._in_table: bool = False
        self._in_thead: bool = False
        self._in_tbody: bool = False
        self._in_tr: bool = False
        self._in_th: bool = False
        self._in_td: bool = False
        self._in_script: bool = False
        self._in_style: bool = False

        # Current table accumulation.
        self._current_headers: list[str] = []
        self._current_rows: list[list[str]] = []
        self._current_row_cells: list[str] = []
        self._cell_text: list[str] = []
        self._header_row_found: bool = False
        self._table_count: int = 0
        self._row_count: int = 0

    # ------------------------------------------------------------------
    # HTMLParser callbacks
    # ------------------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()

        if tag_lower == "script":
            self._in_script = True
            return
        if tag_lower == "style":
            self._in_style = True
            return

        if tag_lower == "table":
            self._start_table()
        elif tag_lower == "thead":
            self._in_thead = True
        elif tag_lower == "tbody":
            self._in_tbody = True
        elif tag_lower == "tr" and self._in_table:
            self._in_tr = True
            self._current_row_cells = []
        elif tag_lower == "th" and self._in_tr:
            self._in_th = True
            self._cell_text = []
        elif tag_lower == "td" and self._in_tr:
            self._in_td = True
            self._cell_text = []

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()

        if tag_lower == "script":
            self._in_script = False
            return
        if tag_lower == "style":
            self._in_style = False
            return

        if tag_lower == "th" and self._in_th:
            self._in_th = False
            self._current_row_cells.append("".join(self._cell_text).strip())
            self._cell_text = []

        elif tag_lower == "td" and self._in_td:
            self._in_td = False
            self._current_row_cells.append("".join(self._cell_text).strip())
            self._cell_text = []

        elif tag_lower == "tr" and self._in_tr:
            self._in_tr = False
            self._finish_row()

        elif tag_lower == "thead":
            self._in_thead = False

        elif tag_lower == "tbody":
            self._in_tbody = False

        elif tag_lower == "table" and self._in_table:
            self._finish_table()

    def handle_data(self, data: str) -> None:
        if self._in_script or self._in_style:
            return

        # Accumulate all visible text for fallback extraction.
        stripped = data.strip()
        if stripped:
            self.all_text_chunks.append(stripped)

        # Accumulate cell text.
        if self._in_th or self._in_td:
            self._cell_text.append(data)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _start_table(self) -> None:
        """Begin tracking a new ``<table>``."""
        if self._table_count >= _MAX_TABLES:
            return
        self._in_table = True
        self._current_headers = []
        self._current_rows = []
        self._header_row_found = False
        self._row_count = 0

    def _finish_row(self) -> None:
        """Process a completed ``<tr>``."""
        cells = self._current_row_cells
        if not cells:
            return

        # Determine if this row is a header row.
        if not self._header_row_found:
            if self._in_thead or self._is_header_row(cells):
                self._current_headers = [c.strip().lower() for c in cells]
                self._header_row_found = True
                return

        # Data row — only collect if we have headers.
        if self._header_row_found and self._row_count < _MAX_ROWS_PER_TABLE:
            self._current_rows.append(list(cells))
            self._row_count += 1

    def _finish_table(self) -> None:
        """Complete a ``<table>`` and decide whether to keep it."""
        self._in_table = False
        self._table_count += 1

        if not self._current_headers or not self._current_rows:
            return

        # Only keep tables with security-relevant headers.
        if self._is_security_table(self._current_headers):
            self.tables.append(
                _ExtractedTable(
                    headers=list(self._current_headers),
                    rows=list(self._current_rows),
                )
            )

    @staticmethod
    def _is_header_row(cells: list[str]) -> bool:
        """Heuristic: check if cells look like header labels.

        A row is considered a header row if it contains at least
        ``_MIN_SECURITY_HEADERS`` security-related keywords.
        """
        lowered = [c.strip().lower() for c in cells]
        matches = sum(
            1
            for cell in lowered
            if any(kw in cell for kw in _SECURITY_HEADER_KEYWORDS)
        )
        return matches >= _MIN_SECURITY_HEADERS

    @staticmethod
    def _is_security_table(headers: list[str]) -> bool:
        """Check if a table header set contains enough security keywords."""
        matches = sum(
            1
            for h in headers
            if any(kw in h for kw in _SECURITY_HEADER_KEYWORDS)
        )
        return matches >= _MIN_SECURITY_HEADERS
