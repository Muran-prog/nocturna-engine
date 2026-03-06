"""Asynchronous event bus for low-coupling component communication."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

import structlog
from structlog.stdlib import BoundLogger

from nocturna_engine.core.event_contract import (
    DEFAULT_EVENT_ALIASES,
    build_reverse_aliases as build_event_reverse_aliases,
    normalize_event_payload,
)
from nocturna_engine.utils.async_helpers import TRANSIENT_RETRY_EXCEPTIONS, retry_async, with_timeout


@dataclass(slots=True, frozen=True)
class Event:
    """Represents one emitted domain event.

    Attributes:
        name: Event name such as `on_scan_started`.
        payload: Structured event data.
        timestamp: UTC event timestamp.
        critical: Whether handler failures should raise.
        source: Identifier of the component that published the event.
    """

    name: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    critical: bool = False
    source: str = ""

EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """Async pub/sub bus used by core and plugins."""

    _ENGINE_LIFECYCLE_EVENTS: frozenset[str] = frozenset({
        "on_scan_started", "on_scan_finished", "scan_started", "scan_completed",
        "on_phase_started", "on_phase_finished", "on_phase_failed",
    })

    def __init__(
        self,
        handler_timeout_seconds: float = 5.0,
        handler_retries: int = 1,
        logger: BoundLogger | None = None,
        enable_v2_bridge: bool = False,
        alias_map: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        """Initialize event bus.

        Args:
            handler_timeout_seconds: Timeout per handler invocation.
            handler_retries: Retries for transient handler failures.
            logger: Optional structured logger.
            enable_v2_bridge: Enable schema-versioned payload and alias bridge.
            alias_map: Optional custom event alias map.
        """

        self._handler_timeout_seconds = handler_timeout_seconds
        self._handler_retries = handler_retries
        self._logger = logger or structlog.get_logger("event_bus")
        self._subscribers: dict[str, set[EventHandler]] = defaultdict(set)
        self._enable_v2_bridge = bool(enable_v2_bridge)
        self._alias_map = dict(alias_map or DEFAULT_EVENT_ALIASES)
        self._reverse_alias_map = self._build_reverse_aliases(self._alias_map)
        self._handler_error_count: dict[str, int] = {}
        self._closed = False

    def configure_v2_bridge(
        self,
        *,
        enabled: bool,
        alias_map: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        """Enable/disable v2 event bridge and optionally replace alias map."""

        self._enable_v2_bridge = bool(enabled)
        if alias_map is not None:
            self._alias_map = dict(alias_map)
            self._reverse_alias_map = self._build_reverse_aliases(self._alias_map)

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        """Subscribe async handler to one event.

        Args:
            event_name: Event name or `*` for wildcard.
            handler: Async callable receiving an `Event`.
        """

        if self._closed:
            raise RuntimeError("EventBus is closed")
        self._subscribers[event_name].add(handler)

    def unsubscribe(self, event_name: str, handler: EventHandler) -> None:
        """Unsubscribe async handler.

        Args:
            event_name: Event name or `*`.
            handler: Handler to remove.
        """

        if event_name in self._subscribers:
            self._subscribers[event_name].discard(handler)
            if not self._subscribers[event_name]:
                del self._subscribers[event_name]

    async def publish(self, event_name: str, payload: dict[str, Any] | None = None, *, critical: bool = False, source: str = "") -> None:
        """Publish one event to all relevant subscribers.

        Args:
            event_name: Event name.
            payload: Optional event payload.
            critical: If True, raise RuntimeError when any handler fails.
            source: Identifier of the publishing component.
        """

        if self._closed:
            self._logger.warning("publish_after_close", event_name=event_name)
            return

        normalized_payload = dict(payload) if payload else {}
        if self._enable_v2_bridge:
            normalized_payload = self._normalize_payload(event_name, normalized_payload)

        if event_name in self._ENGINE_LIFECYCLE_EVENTS and source and source != "engine":
            self._logger.warning(
                "lifecycle_event_from_non_engine_source",
                event_name=event_name,
                source=source,
            )

        normalized_payload.setdefault("_event_source", source)

        event_names = [event_name]
        if self._enable_v2_bridge:
            event_names = self._expand_event_names(event_name)

        wildcard_handlers = list(self._subscribers.get("*", set()))
        for current_event_name in event_names:
            event = Event(name=current_event_name, payload=MappingProxyType(dict(normalized_payload)), critical=critical, source=source)
            handlers = list(self._subscribers.get(current_event_name, set()))
            if not handlers:
                continue

            await self._dispatch_handlers(
                event_name=current_event_name,
                event=event,
                handlers=handlers,
                critical=critical,
            )

        # Wildcard subscriptions represent one logical published event, even if
        # alias bridge expands to multiple event names.
        if wildcard_handlers and event_name != "*":
            await self._dispatch_handlers(
                event_name=event_name,
                event=Event(name=event_name, payload=MappingProxyType(dict(normalized_payload)), critical=critical, source=source),
                handlers=wildcard_handlers,
                critical=critical,
            )

    async def close(self) -> None:
        """Clear all subscriptions and release bus resources."""

        self._closed = True
        self._subscribers.clear()

    async def _dispatch_handler(self, handler: EventHandler, event: Event) -> None:
        """Invoke one handler with retry and timeout controls.

        Args:
            handler: Event handler callback.
            event: Emitted event object.
        """

        async def _operation() -> None:
            await with_timeout(
                handler(event),
                timeout_seconds=self._handler_timeout_seconds,
                operation_name=f"event_handler:{event.name}",
            )

        await retry_async(
            _operation,
            retries=self._handler_retries,
            retry_exceptions=TRANSIENT_RETRY_EXCEPTIONS,
        )

    async def _dispatch_handlers(
        self,
        *,
        event_name: str,
        event: Event,
        handlers: list[EventHandler],
        critical: bool = False,
    ) -> None:
        results = await asyncio.gather(
            *(self._dispatch_handler(handler, event) for handler in handlers),
            return_exceptions=True,
        )

        errors: list[BaseException] = []
        for result in results:
            if isinstance(result, BaseException):
                self._handler_error_count[event_name] = self._handler_error_count.get(event_name, 0) + 1
                self._logger.error(
                    "event_handler_failed",
                    event_name=event_name,
                    error=str(result),
                )
                errors.append(result)

        if critical and errors:
            msg = f"{len(errors)} handler(s) failed for critical event '{event_name}': " + "; ".join(str(e) for e in errors)
            raise RuntimeError(msg)

    def get_handler_error_counts(self) -> dict[str, int]:
        """Return cumulative handler error counts per event name.

        Returns:
            dict[str, int]: Mapping of event names to error counts.
        """

        return dict(self._handler_error_count)

    @staticmethod
    def _build_reverse_aliases(alias_map: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        return build_event_reverse_aliases(alias_map)

    def _expand_event_names(self, event_name: str) -> list[str]:
        names: list[str] = [event_name]
        names.extend(self._alias_map.get(event_name, tuple()))
        names.extend(self._reverse_alias_map.get(event_name, tuple()))
        unique: list[str] = []
        seen: set[str] = set()
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            unique.append(name)
        return unique

    @staticmethod
    def _normalize_payload(event_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        return normalize_event_payload(event_name, payload)
