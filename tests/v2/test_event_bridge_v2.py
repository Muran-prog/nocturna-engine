"""Tests for v2 event contract alias bridge."""

from __future__ import annotations

import pytest

from nocturna_engine.core.event_bus import Event, EventBus


@pytest.mark.asyncio()
async def test_publish_legacy_event_delivers_v2_alias_with_schema_payload() -> None:
    bus = EventBus(enable_v2_bridge=True)
    legacy_received: list[Event] = []
    v2_received: list[Event] = []

    async def legacy_handler(event: Event) -> None:
        legacy_received.append(event)

    async def v2_handler(event: Event) -> None:
        v2_received.append(event)

    bus.subscribe("on_tool_started", legacy_handler)
    bus.subscribe("tool.started", v2_handler)
    await bus.publish("on_tool_started", {"request_id": "req-1"})

    assert len(legacy_received) == 1
    assert len(v2_received) == 1
    assert v2_received[0].payload["schema_version"] == "2.0.0"
    assert v2_received[0].payload["event_type"] == "on_tool_started"


@pytest.mark.asyncio()
async def test_publish_v2_event_delivers_legacy_alias() -> None:
    bus = EventBus(enable_v2_bridge=True)
    legacy_received: list[str] = []
    v2_received: list[str] = []

    async def legacy_handler(event: Event) -> None:
        legacy_received.append(event.name)

    async def v2_handler(event: Event) -> None:
        v2_received.append(event.name)

    bus.subscribe("on_tool_finished", legacy_handler)
    bus.subscribe("tool.finished", v2_handler)
    await bus.publish("tool.finished", {"request_id": "req-2"})

    assert "tool.finished" in v2_received
    assert "on_tool_finished" in legacy_received

