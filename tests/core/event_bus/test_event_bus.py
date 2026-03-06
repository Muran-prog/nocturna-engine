"""Comprehensive edge-case tests for EventBus."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from unittest.mock import AsyncMock

from nocturna_engine.core.event_bus import Event, EventBus
from nocturna_engine.exceptions import NocturnaTimeoutError


# ---------------------------------------------------------------------------
# Event dataclass edge cases
# ---------------------------------------------------------------------------


class TestEventDataclass:
    """Edge cases for the frozen Event dataclass."""

    async def test_event_is_frozen_cannot_set_name(self):
        event = Event(name="x")
        try:
            event.name = "y"  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass

    async def test_event_is_frozen_cannot_set_payload(self):
        event = Event(name="x")
        try:
            event.payload = {"a": 1}  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass

    async def test_event_default_payload_is_empty_dict(self):
        event = Event(name="x")
        assert event.payload == {}

    async def test_event_default_payloads_are_independent(self):
        e1 = Event(name="a")
        e2 = Event(name="b")
        e1.payload["key"] = "val"
        assert "key" not in e2.payload

    async def test_event_timestamp_defaults_to_utc_now(self):
        before = datetime.now(UTC)
        event = Event(name="x")
        after = datetime.now(UTC)
        assert before <= event.timestamp <= after

    async def test_event_custom_timestamp_preserved(self):
        ts = datetime(2020, 1, 1, tzinfo=UTC)
        event = Event(name="x", timestamp=ts)
        assert event.timestamp == ts


# ---------------------------------------------------------------------------
# Subscribe / unsubscribe edge cases
# ---------------------------------------------------------------------------


class TestSubscribeUnsubscribe:
    """Subscribe/unsubscribe edge cases."""

    async def test_subscribe_same_handler_twice_deduplicates(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("evt", handler)
        bus.subscribe("evt", handler)
        await bus.publish("evt")
        # Handler stored in set → single instance, called once
        handler.assert_awaited_once()

    async def test_unsubscribe_nonexistent_handler_no_error(self):
        bus = EventBus()
        handler = AsyncMock()
        # No subscription at all – must not raise
        bus.unsubscribe("evt", handler)

    async def test_unsubscribe_handler_not_in_subscriber_set(self):
        bus = EventBus()
        h1 = AsyncMock()
        h2 = AsyncMock()
        bus.subscribe("evt", h1)
        bus.unsubscribe("evt", h2)  # h2 never subscribed – should be silent
        await bus.publish("evt")
        h1.assert_awaited_once()

    async def test_unsubscribe_removes_empty_key(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("evt", handler)
        bus.unsubscribe("evt", handler)
        assert "evt" not in bus._subscribers

    async def test_subscribe_wildcard(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("*", handler)
        await bus.publish("anything")
        handler.assert_awaited_once()

    async def test_wildcard_subscriber_receives_all_events(self):
        bus = EventBus()
        received: list[str] = []

        async def catch_all(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("*", catch_all)
        await bus.publish("alpha")
        await bus.publish("beta")
        assert "alpha" in received
        assert "beta" in received
        assert len(received) == 2

    async def test_unsubscribe_wildcard(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("*", handler)
        bus.unsubscribe("*", handler)
        await bus.publish("anything")
        handler.assert_not_awaited()


# ---------------------------------------------------------------------------
# Publish edge cases
# ---------------------------------------------------------------------------


class TestPublish:
    """Publish edge cases."""

    async def test_publish_no_subscribers_no_error(self):
        bus = EventBus()
        await bus.publish("ghost_event")  # must not raise

    async def test_publish_payload_mutation_safety(self):
        """Handler mutating payload must be rejected — payload is immutable."""
        bus = EventBus()
        payloads_seen: list[dict[str, Any]] = []
        mutation_errors: list[Exception] = []

        async def mutating_handler(event: Event) -> None:
            try:
                event.payload["injected"] = True  # type: ignore[index]
            except TypeError as exc:
                mutation_errors.append(exc)
            payloads_seen.append(dict(event.payload))

        async def innocent_handler(event: Event) -> None:
            payloads_seen.append(dict(event.payload))

        bus.subscribe("evt", mutating_handler)
        bus.subscribe("evt", innocent_handler)
        await bus.publish("evt", {"key": "val"})
        # Payload is wrapped in MappingProxyType — mutation raises TypeError.
        assert len(mutation_errors) >= 1
        # Neither handler sees 'injected' because mutation was blocked.
        for seen in payloads_seen:
            assert "injected" not in seen
        # Original caller payload is also unmodified.
        original_payload = {"key": "val"}
        await bus.publish("evt", original_payload)
        assert "injected" not in original_payload

    async def test_publish_empty_payload_defaults_to_empty_dict(self):
        bus = EventBus()
        received: list[dict[str, Any]] = []

        async def handler(event: Event) -> None:
            received.append(event.payload)

        bus.subscribe("evt", handler)
        await bus.publish("evt")
        assert received[0] == {"_event_source": ""}

    async def test_publish_none_payload_treated_as_empty(self):
        bus = EventBus()
        received: list[dict[str, Any]] = []

        async def handler(event: Event) -> None:
            received.append(event.payload)

        bus.subscribe("evt", handler)
        await bus.publish("evt", None)
        assert received[0].get("_event_source") == ""
        assert "schema_version" not in received[0]

    async def test_wildcard_not_dispatched_when_event_name_is_star(self):
        """Publishing '*' directly should NOT double-dispatch wildcard handlers."""
        bus = EventBus()
        call_count = 0

        async def handler(event: Event) -> None:
            nonlocal call_count
            call_count += 1

        bus.subscribe("*", handler)
        # event_name="*" causes direct subscriber match, but wildcard
        # logic guards against event_name == "*" to avoid double dispatch
        await bus.publish("*")
        assert call_count == 1


# ---------------------------------------------------------------------------
# Handler timeout edge cases
# ---------------------------------------------------------------------------


class TestHandlerTimeout:
    """Timeout enforcement."""

    async def test_slow_handler_times_out(self):
        bus = EventBus(handler_timeout_seconds=0.05, handler_retries=0)
        timed_out = asyncio.Event()

        async def slow_handler(event: Event) -> None:
            await asyncio.sleep(10)

        bus.subscribe("evt", slow_handler)
        # Should not raise (gather returns exceptions), but handler fails
        await bus.publish("evt")
        # Bus logs warning but does not propagate – test passes if no raise

    async def test_fast_handler_not_affected_by_timeout(self):
        bus = EventBus(handler_timeout_seconds=5.0, handler_retries=0)
        called = asyncio.Event()

        async def fast_handler(event: Event) -> None:
            called.set()

        bus.subscribe("evt", fast_handler)
        await bus.publish("evt")
        assert called.is_set()


# ---------------------------------------------------------------------------
# Handler retry edge cases
# ---------------------------------------------------------------------------


class TestHandlerRetry:
    """Retry behavior for transient failures."""

    async def test_transient_failure_retried(self):
        bus = EventBus(handler_timeout_seconds=2.0, handler_retries=2)
        attempt_count = 0

        async def flaky_handler(event: Event) -> None:
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise ConnectionError("transient")

        bus.subscribe("evt", flaky_handler)
        await bus.publish("evt")
        assert attempt_count == 3  # 1 initial + 2 retries

    async def test_permanent_failure_exhausts_retries(self):
        bus = EventBus(handler_timeout_seconds=2.0, handler_retries=1)
        attempt_count = 0

        async def always_fail(event: Event) -> None:
            nonlocal attempt_count
            attempt_count += 1
            raise ConnectionError("permanent")

        bus.subscribe("evt", always_fail)
        # gather returns exceptions, so publish won't propagate
        await bus.publish("evt")
        assert attempt_count == 2  # 1 initial + 1 retry

    async def test_zero_retries_means_single_attempt(self):
        bus = EventBus(handler_retries=0)
        attempt_count = 0

        async def fail_handler(event: Event) -> None:
            nonlocal attempt_count
            attempt_count += 1
            raise RuntimeError("fail")

        bus.subscribe("evt", fail_handler)
        await bus.publish("evt")
        assert attempt_count == 1


# ---------------------------------------------------------------------------
# Handler failure isolation
# ---------------------------------------------------------------------------


class TestHandlerIsolation:
    """One failing handler must not prevent others from running."""

    async def test_failing_handler_does_not_block_others(self):
        bus = EventBus(handler_retries=0)
        success = asyncio.Event()

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("boom")

        async def good_handler(event: Event) -> None:
            success.set()

        bus.subscribe("evt", bad_handler)
        bus.subscribe("evt", good_handler)
        await bus.publish("evt")
        assert success.is_set()

    async def test_multiple_failing_handlers_all_logged(self):
        bus = EventBus(handler_retries=0)
        call_count = 0

        async def fail1(event: Event) -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError("fail1")

        async def fail2(event: Event) -> None:
            nonlocal call_count
            call_count += 1
            raise TypeError("fail2")

        bus.subscribe("evt", fail1)
        bus.subscribe("evt", fail2)
        await bus.publish("evt")
        assert call_count == 2  # Both attempted


# ---------------------------------------------------------------------------
# V2 bridge edge cases
# ---------------------------------------------------------------------------


class TestV2Bridge:
    """V2 bridge: alias expansion, payload normalization, bidirectional."""

    async def test_v2_bridge_disabled_no_alias_expansion(self):
        bus = EventBus(enable_v2_bridge=False)
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("scan.started", handler)
        await bus.publish("on_scan_started")
        assert "scan.started" not in received

    async def test_v2_bridge_enabled_alias_expansion(self):
        bus = EventBus(enable_v2_bridge=True)
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("scan.started", handler)
        await bus.publish("on_scan_started")
        assert "scan.started" in received

    async def test_v2_bridge_bidirectional_reverse(self):
        """Publishing v2 name reaches v1 subscribers."""
        bus = EventBus(enable_v2_bridge=True)
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("on_scan_started", handler)
        await bus.publish("scan.started")
        assert "on_scan_started" in received

    async def test_v2_bridge_payload_normalization(self):
        bus = EventBus(enable_v2_bridge=True)
        received_payload: list[dict[str, Any]] = []

        async def handler(event: Event) -> None:
            received_payload.append(event.payload)

        bus.subscribe("on_scan_started", handler)
        await bus.publish("on_scan_started", {"target": "example.com"})
        p = received_payload[0]
        assert p["target"] == "example.com"
        assert "schema_version" in p
        assert "event_type" in p
        assert "emitted_at" in p

    async def test_v2_bridge_disabled_no_payload_normalization(self):
        bus = EventBus(enable_v2_bridge=False)
        received_payload: list[dict[str, Any]] = []

        async def handler(event: Event) -> None:
            received_payload.append(event.payload)

        bus.subscribe("evt", handler)
        await bus.publish("evt", {"key": "val"})
        p = received_payload[0]
        assert p["key"] == "val"
        assert "schema_version" not in p
        assert p.get("_event_source") == ""

    async def test_v2_bridge_custom_alias_map(self):
        custom = {"legacy_evt": ("v2.evt",)}
        bus = EventBus(enable_v2_bridge=True, alias_map=custom)
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("v2.evt", handler)
        await bus.publish("legacy_evt")
        assert "v2.evt" in received

    async def test_v2_bridge_custom_alias_no_default_aliases(self):
        """Custom alias map replaces defaults entirely."""
        custom = {"my_event": ("my.event",)}
        bus = EventBus(enable_v2_bridge=True, alias_map=custom)
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("scan.started", handler)
        await bus.publish("on_scan_started")
        # Default alias should NOT be used since custom replaces it
        assert "scan.started" not in received

    async def test_v2_bridge_wildcard_receives_original_event_name_only(self):
        """Wildcard handler receives once with original event name, not aliases."""
        bus = EventBus(enable_v2_bridge=True)
        received_names: list[str] = []

        async def handler(event: Event) -> None:
            received_names.append(event.name)

        bus.subscribe("*", handler)
        await bus.publish("on_scan_started")
        # Wildcard should only fire once with original name
        assert received_names.count("on_scan_started") == 1
        assert len(received_names) == 1

    async def test_expand_event_names_no_duplicates(self):
        """Alias expansion should not produce duplicate names."""
        bus = EventBus(enable_v2_bridge=True)
        # on_scan_started -> scan.started and scan_started -> scan.started
        # overlapping aliases, but expansion for a single name should be unique
        names = bus._expand_event_names("on_scan_started")
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# configure_v2_bridge
# ---------------------------------------------------------------------------


class TestConfigureV2Bridge:
    """configure_v2_bridge runtime reconfiguration."""

    async def test_configure_v2_bridge_enable(self):
        bus = EventBus(enable_v2_bridge=False)
        bus.configure_v2_bridge(enabled=True)
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("scan.started", handler)
        await bus.publish("on_scan_started")
        assert "scan.started" in received

    async def test_configure_v2_bridge_disable(self):
        bus = EventBus(enable_v2_bridge=True)
        bus.configure_v2_bridge(enabled=False)
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("scan.started", handler)
        await bus.publish("on_scan_started")
        assert "scan.started" not in received

    async def test_configure_v2_bridge_replace_alias_map(self):
        bus = EventBus(enable_v2_bridge=True)
        bus.configure_v2_bridge(enabled=True, alias_map={"custom": ("alias.custom",)})
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("alias.custom", handler)
        await bus.publish("custom")
        assert "alias.custom" in received

    async def test_configure_v2_bridge_none_alias_map_keeps_existing(self):
        custom = {"my_event": ("my.event",)}
        bus = EventBus(enable_v2_bridge=True, alias_map=custom)
        bus.configure_v2_bridge(enabled=True, alias_map=None)
        # Should keep old alias map
        received: list[str] = []

        async def handler(event: Event) -> None:
            received.append(event.name)

        bus.subscribe("my.event", handler)
        await bus.publish("my_event")
        assert "my.event" in received


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestClose:
    """close() clears all subscriptions."""

    async def test_close_clears_all_subscribers(self):
        bus = EventBus()
        bus.subscribe("evt1", AsyncMock())
        bus.subscribe("evt2", AsyncMock())
        bus.subscribe("*", AsyncMock())
        await bus.close()
        assert len(bus._subscribers) == 0

    async def test_close_then_publish_no_handlers_called(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("evt", handler)
        await bus.close()
        await bus.publish("evt")
        handler.assert_not_awaited()


# ---------------------------------------------------------------------------
# Concurrent publish safety
# ---------------------------------------------------------------------------


class TestConcurrentPublish:
    """Concurrent publish must not corrupt state."""

    async def test_concurrent_publishes_no_lost_events(self):
        bus = EventBus()
        counter = {"count": 0}
        lock = asyncio.Lock()

        async def counting_handler(event: Event) -> None:
            async with lock:
                counter["count"] += 1

        bus.subscribe("evt", counting_handler)
        await asyncio.gather(*(bus.publish("evt") for _ in range(50)))
        assert counter["count"] == 50

    async def test_concurrent_publish_different_events(self):
        bus = EventBus()
        received: dict[str, int] = {}
        lock = asyncio.Lock()

        async def handler(event: Event) -> None:
            async with lock:
                received[event.name] = received.get(event.name, 0) + 1

        bus.subscribe("alpha", handler)
        bus.subscribe("beta", handler)
        tasks = [bus.publish("alpha") for _ in range(20)] + [
            bus.publish("beta") for _ in range(20)
        ]
        await asyncio.gather(*tasks)
        assert received["alpha"] == 20
        assert received["beta"] == 20


# ---------------------------------------------------------------------------
# Handler ordering not guaranteed (gather)
# ---------------------------------------------------------------------------


class TestHandlerOrdering:
    """Handler execution order is NOT guaranteed since gather is used."""

    async def test_handler_order_not_guaranteed(self):
        bus = EventBus()
        order: list[int] = []
        barrier = asyncio.Barrier(3)

        async def handler_a(event: Event) -> None:
            await barrier.wait()
            order.append(1)

        async def handler_b(event: Event) -> None:
            await barrier.wait()
            order.append(2)

        async def handler_c(event: Event) -> None:
            await barrier.wait()
            order.append(3)

        bus.subscribe("evt", handler_a)
        bus.subscribe("evt", handler_b)
        bus.subscribe("evt", handler_c)
        await bus.publish("evt")
        # All three ran – order may vary
        assert sorted(order) == [1, 2, 3]


# ---------------------------------------------------------------------------
# Handler exception logging (structural, not structlog internals)
# ---------------------------------------------------------------------------


class TestHandlerExceptionLogging:
    """Verify failed handlers are logged via warning (behavioral check)."""

    async def test_handler_exception_does_not_propagate(self):
        bus = EventBus(handler_retries=0)

        async def bad(event: Event) -> None:
            raise RuntimeError("boom")

        bus.subscribe("evt", bad)
        # Must not propagate
        await bus.publish("evt")

    async def test_handler_timeout_exception_does_not_propagate(self):
        bus = EventBus(handler_timeout_seconds=0.05, handler_retries=0)

        async def slow(event: Event) -> None:
            await asyncio.sleep(10)

        bus.subscribe("evt", slow)
        await bus.publish("evt")


# ---------------------------------------------------------------------------
# Critical event handling (SEC-5)
# ---------------------------------------------------------------------------


class TestCriticalEvents:
    """Tests for critical=True event handling."""

    async def test_critical_event_raises_on_handler_failure(self):
        bus = EventBus(handler_retries=0)

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("audit failed")

        bus.subscribe("audit", bad_handler)
        with pytest.raises(RuntimeError, match="handler.*failed.*critical.*audit"):
            await bus.publish("audit", critical=True)

    async def test_critical_false_does_not_raise(self):
        bus = EventBus(handler_retries=0)

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("non-critical fail")

        bus.subscribe("evt", bad_handler)
        # Should NOT raise
        await bus.publish("evt", critical=False)

    async def test_critical_default_is_false(self):
        bus = EventBus(handler_retries=0)

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("default fail")

        bus.subscribe("evt", bad_handler)
        # Should NOT raise (default critical=False)
        await bus.publish("evt")

    async def test_critical_event_collects_multiple_errors(self):
        bus = EventBus(handler_retries=0)

        async def fail1(event: Event) -> None:
            raise ValueError("error1")

        async def fail2(event: Event) -> None:
            raise TypeError("error2")

        bus.subscribe("audit", fail1)
        bus.subscribe("audit", fail2)
        with pytest.raises(RuntimeError, match="2 handler.*failed"):
            await bus.publish("audit", critical=True)

    async def test_critical_event_good_handlers_still_run(self):
        bus = EventBus(handler_retries=0)
        success = asyncio.Event()

        async def good_handler(event: Event) -> None:
            success.set()

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("fail")

        bus.subscribe("audit", good_handler)
        bus.subscribe("audit", bad_handler)
        with pytest.raises(RuntimeError):
            await bus.publish("audit", critical=True)
        assert success.is_set()


# ---------------------------------------------------------------------------
# Handler error count tracking (SEC-5)
# ---------------------------------------------------------------------------


class TestHandlerErrorCounts:
    """Tests for handler error count tracking."""

    async def test_error_count_increments(self):
        bus = EventBus(handler_retries=0)

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("fail")

        bus.subscribe("evt", bad_handler)
        await bus.publish("evt")
        counts = bus.get_handler_error_counts()
        assert counts["evt"] == 1

    async def test_error_count_accumulates(self):
        bus = EventBus(handler_retries=0)

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("fail")

        bus.subscribe("evt", bad_handler)
        await bus.publish("evt")
        await bus.publish("evt")
        counts = bus.get_handler_error_counts()
        assert counts["evt"] == 2

    async def test_error_count_per_event_name(self):
        bus = EventBus(handler_retries=0)

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("fail")

        bus.subscribe("alpha", bad_handler)
        bus.subscribe("beta", bad_handler)
        await bus.publish("alpha")
        await bus.publish("beta")
        await bus.publish("beta")
        counts = bus.get_handler_error_counts()
        assert counts["alpha"] == 1
        assert counts["beta"] == 2

    async def test_error_count_empty_initially(self):
        bus = EventBus()
        assert bus.get_handler_error_counts() == {}

    async def test_error_count_returns_copy(self):
        bus = EventBus(handler_retries=0)

        async def bad_handler(event: Event) -> None:
            raise RuntimeError("fail")

        bus.subscribe("evt", bad_handler)
        await bus.publish("evt")
        counts = bus.get_handler_error_counts()
        counts["evt"] = 999  # Mutate the returned copy
        assert bus.get_handler_error_counts()["evt"] == 1  # Original unchanged


# ---------------------------------------------------------------------------
# Event dataclass critical field (SEC-5)
# ---------------------------------------------------------------------------


class TestEventCriticalField:
    """Tests for Event.critical field."""

    async def test_event_critical_defaults_false(self):
        event = Event(name="x")
        assert event.critical is False

    async def test_event_critical_set_true(self):
        event = Event(name="x", critical=True)
        assert event.critical is True

    async def test_event_critical_frozen(self):
        event = Event(name="x", critical=True)
        try:
            event.critical = False  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass



# ---------------------------------------------------------------------------
# Source attribution (SEC-10)
# ---------------------------------------------------------------------------


class TestSourceAttribution:
    """Tests for event source attribution."""

    async def test_source_passed_to_event(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe("evt", handler)
        await bus.publish("evt", {"key": "val"}, source="my_plugin")
        assert len(received) == 1
        assert received[0].source == "my_plugin"

    async def test_source_defaults_to_empty(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe("evt", handler)
        await bus.publish("evt")
        assert received[0].source == ""

    async def test_source_in_payload_as_event_source(self):
        bus = EventBus()
        received_payload: list[dict[str, Any]] = []

        async def handler(event: Event) -> None:
            received_payload.append(event.payload)

        bus.subscribe("evt", handler)
        await bus.publish("evt", {"data": 1}, source="scanner")
        assert received_payload[0]["_event_source"] == "scanner"

    async def test_source_does_not_overwrite_existing_event_source(self):
        bus = EventBus()
        received_payload: list[dict[str, Any]] = []

        async def handler(event: Event) -> None:
            received_payload.append(event.payload)

        bus.subscribe("evt", handler)
        await bus.publish("evt", {"_event_source": "original"}, source="new")
        assert received_payload[0]["_event_source"] == "original"

    async def test_lifecycle_event_from_non_engine_source_warns(self):
        """Publishing a lifecycle event with non-engine source logs warning."""
        import structlog
        captured: list[dict[str, Any]] = []

        def capture_factory(*args: Any, **kwargs: Any) -> Any:
            from structlog.testing import LogCapture
            lc = LogCapture()
            captured.clear()

            class _Proxy:
                def __getattr__(self, name: str) -> Any:
                    def method(*a: Any, **kw: Any) -> Any:
                        captured.append({"method": name, **kw})
                    return method
            return _Proxy()

        # Use a mock logger to capture warnings
        from unittest.mock import MagicMock
        mock_logger = MagicMock()
        bus = EventBus(logger=mock_logger)
        await bus.publish("on_scan_started", source="rogue_plugin")
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "lifecycle_event_from_non_engine_source"
        assert call_args[1]["source"] == "rogue_plugin"
        assert call_args[1]["event_name"] == "on_scan_started"

    async def test_lifecycle_event_from_engine_source_no_warning(self):
        from unittest.mock import MagicMock
        mock_logger = MagicMock()
        bus = EventBus(logger=mock_logger)
        await bus.publish("on_scan_started", source="engine")
        mock_logger.warning.assert_not_called()

    async def test_lifecycle_event_without_source_no_warning(self):
        from unittest.mock import MagicMock
        mock_logger = MagicMock()
        bus = EventBus(logger=mock_logger)
        await bus.publish("on_scan_started")
        mock_logger.warning.assert_not_called()

    async def test_non_lifecycle_event_from_any_source_no_warning(self):
        from unittest.mock import MagicMock
        mock_logger = MagicMock()
        bus = EventBus(logger=mock_logger)
        await bus.publish("custom_event", source="any_plugin")
        mock_logger.warning.assert_not_called()


class TestEventSourceField:
    """Tests for Event.source field."""

    async def test_event_source_defaults_empty(self):
        event = Event(name="x")
        assert event.source == ""

    async def test_event_source_set(self):
        event = Event(name="x", source="my_plugin")
        assert event.source == "my_plugin"

    async def test_event_source_frozen(self):
        event = Event(name="x", source="plugin")
        try:
            event.source = "other"  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass