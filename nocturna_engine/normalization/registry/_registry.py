"""Parser registry with format-aware lookup."""

from __future__ import annotations

import fnmatch
from typing import Any

import structlog

from nocturna_engine.normalization.detector import InputFormat
from nocturna_engine.normalization.errors import ParserNotFoundError, ParserRegistrationError
from nocturna_engine.normalization.registry._entry import _RegistryEntry

logger = structlog.get_logger("normalization.registry")


class ParserRegistry:
    """Global registry for normalization parsers with format-based lookup.

    Parsers register via the ``@register_parser`` decorator or explicit
    ``register()`` calls. Lookup is by format, with optional tool-name refinement.
    """

    def __init__(self) -> None:
        # format → list of (parser_name, parser_class, tool_patterns)
        self._by_format: dict[InputFormat, list[_RegistryEntry]] = {}
        # parser_name → parser_class (for direct name lookup)
        self._by_name: dict[str, type[Any]] = {}

    def register(
        self,
        parser_class: type[Any],
        *,
        name: str,
        formats: list[InputFormat],
        tool_patterns: list[str] | None = None,
        priority: int = 0,
    ) -> None:
        """Register a parser class for one or more input formats.

        Args:
            parser_class: Parser class (must be a BaseParser subclass).
            name: Unique parser name.
            formats: Input formats this parser handles.
            tool_patterns: Optional tool name patterns for disambiguation.
            priority: Higher priority parsers are tried first.

        Raises:
            ParserRegistrationError: If name is already registered.
        """
        normalized_name = name.strip().lower()
        if not normalized_name:
            raise ParserRegistrationError("Parser name must be non-empty.")

        if normalized_name in self._by_name:
            existing = self._by_name[normalized_name]
            if existing is not parser_class:
                raise ParserRegistrationError(
                    f"Parser name already registered: {normalized_name!r}.",
                )
            # Same class — check if parameters differ.
            existing_entry = self._find_entry(normalized_name)
            if existing_entry is not None:
                new_patterns = sorted(p.strip().lower() for p in (tool_patterns or []))
                old_patterns = sorted(existing_entry.tool_patterns)
                new_formats = frozenset(formats)
                if (
                    new_formats != existing_entry.formats
                    or new_patterns != old_patterns
                    or priority != existing_entry.priority
                ):
                    raise ParserRegistrationError(
                        f"Re-registration of {normalized_name!r} with different parameters. "
                        f"Existing formats={existing_entry.formats}, tool_patterns={old_patterns}, priority={existing_entry.priority}; "
                        f"New formats={new_formats}, tool_patterns={new_patterns}, priority={priority}.",
                    )
            return

        entry = _RegistryEntry(
            name=normalized_name,
            parser_class=parser_class,
            tool_patterns=[p.strip().lower() for p in (tool_patterns or [])],
            priority=priority,
            formats=frozenset(formats),
        )

        self._by_name[normalized_name] = parser_class
        for fmt in formats:
            entries = self._by_format.setdefault(fmt, [])
            entries.append(entry)
            entries.sort(key=lambda e: e.priority, reverse=True)

        logger.debug(
            "parser_registered",
            name=normalized_name,
            formats=[f.value for f in formats],
            tool_patterns=entry.tool_patterns,
            priority=priority,
        )

    def lookup(
        self,
        fmt: InputFormat,
        *,
        tool_hint: str | None = None,
    ) -> type[Any]:
        """Find the best parser class for a given format and optional tool hint.

        Args:
            fmt: Detected input format.
            tool_hint: Optional tool name for disambiguation.

        Returns:
            type: Parser class to instantiate.

        Raises:
            ParserNotFoundError: If no parser is registered for this format.
        """
        entries = self._by_format.get(fmt)
        if not entries:
            raise ParserNotFoundError(
                f"No parser registered for format: {fmt.value}.",
                context={"format": fmt.value, "tool_hint": tool_hint},
            )

        # If tool_hint is provided, prefer parsers that match.
        if tool_hint is not None:
            normalized_tool = tool_hint.strip().lower()
            for entry in entries:
                if any(fnmatch.fnmatch(normalized_tool, pattern) for pattern in entry.tool_patterns):
                    return entry.parser_class

        # Return highest priority parser.
        return entries[0].parser_class

    def lookup_by_name(self, name: str) -> type[Any] | None:
        """Look up a parser class by its registered name.

        Args:
            name: Parser name.

        Returns:
            type | None: Parser class if found.
        """
        return self._by_name.get(name.strip().lower())

    def list_parsers(self) -> list[dict[str, Any]]:
        """Return metadata for all registered parsers.

        Returns:
            list[dict[str, Any]]: Parser metadata entries.
        """
        result: list[dict[str, Any]] = []
        for name, parser_class in sorted(self._by_name.items()):
            formats_for_parser: list[str] = []
            for fmt, entries in self._by_format.items():
                if any(e.name == name for e in entries):
                    formats_for_parser.append(fmt.value)
            result.append({
                "name": name,
                "class": parser_class.__qualname__,
                "formats": formats_for_parser,
            })
        return result

    def _find_entry(self, name: str) -> _RegistryEntry | None:
        """Find a registry entry by name (internal helper)."""
        for entries in self._by_format.values():
            for entry in entries:
                if entry.name == name:
                    return entry
        return None
