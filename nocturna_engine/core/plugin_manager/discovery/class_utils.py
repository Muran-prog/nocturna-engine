"""Class introspection utilities mixin."""

from __future__ import annotations

from collections.abc import Iterable

from nocturna_engine.interfaces import BaseTool


class PluginClassUtilsMixin:
    """Subclass iteration, deduplication, and package filtering."""

    @staticmethod
    def _iter_subclasses(base_class: type[BaseTool]) -> list[type[BaseTool]]:
        """Collect all transitive subclasses of `base_class`.

        Args:
            base_class: Base class type.

        Returns:
            list[type[BaseTool]]: Discovered subclasses.
        """

        found: set[type[BaseTool]] = set()
        queue = sorted(base_class.__subclasses__(), key=lambda item: (item.__module__, item.__qualname__))
        while queue:
            current = queue.pop(0)
            found.add(current)
            queue.extend(
                sorted(
                    current.__subclasses__(),
                    key=lambda item: (item.__module__, item.__qualname__),
                )
            )
        return sorted(found, key=lambda item: (item.__module__, item.__qualname__))

    @staticmethod
    def _iter_unique_classes(*sources: Iterable[type[BaseTool]]) -> list[type[BaseTool]]:
        seen: set[type[BaseTool]] = set()
        ordered: list[type[BaseTool]] = []
        for source in sources:
            for item in source:
                if item in seen:
                    continue
                seen.add(item)
                ordered.append(item)
        return ordered

    @staticmethod
    def _filter_classes_by_package(
        classes: Iterable[type[BaseTool]],
        package_name: str,
    ) -> list[type[BaseTool]]:
        prefix = f"{package_name}."
        return [
            tool_class
            for tool_class in classes
            if tool_class.__module__ == package_name or tool_class.__module__.startswith(prefix)
        ]
