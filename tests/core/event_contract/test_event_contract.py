"""Comprehensive edge-case tests for event_contract module."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from nocturna_engine.core.event_contract import (
    DEFAULT_EVENT_ALIASES,
    EventV2,
    build_reverse_aliases,
    normalize_event_payload,
)


# ---------------------------------------------------------------------------
# DEFAULT_EVENT_ALIASES completeness
# ---------------------------------------------------------------------------


class TestDefaultEventAliases:
    """Verify structure and completeness of DEFAULT_EVENT_ALIASES."""

    async def test_aliases_is_nonempty_dict(self):
        assert isinstance(DEFAULT_EVENT_ALIASES, dict)
        assert len(DEFAULT_EVENT_ALIASES) > 0

    async def test_all_alias_values_are_tuples_of_strings(self):
        for key, value in DEFAULT_EVENT_ALIASES.items():
            assert isinstance(key, str), f"Key {key!r} is not str"
            assert isinstance(value, tuple), f"Value for {key!r} is not tuple"
            for alias in value:
                assert isinstance(alias, str), f"Alias {alias!r} in {key!r} is not str"

    async def test_known_core_events_present(self):
        expected = [
            "on_scan_started",
            "on_scan_finished",
            "on_tool_error",
            "on_finding_detected",
            "on_policy_invalid",
        ]
        for name in expected:
            assert name in DEFAULT_EVENT_ALIASES, f"Missing alias for {name}"

    async def test_no_alias_maps_to_empty_tuple(self):
        for key, value in DEFAULT_EVENT_ALIASES.items():
            assert len(value) > 0, f"Alias for {key!r} is empty tuple"


# ---------------------------------------------------------------------------
# build_reverse_aliases edge cases
# ---------------------------------------------------------------------------


class TestBuildReverseAliases:
    """Edge cases for reverse alias building."""

    async def test_empty_map_returns_empty(self):
        assert build_reverse_aliases({}) == {}

    async def test_single_alias_reverses(self):
        result = build_reverse_aliases({"a": ("b",)})
        assert result == {"b": ("a",)}

    async def test_symmetric_aliases(self):
        """Two names pointing to overlapping aliases."""
        result = build_reverse_aliases({"x": ("shared",), "y": ("shared",)})
        assert "shared" in result
        assert set(result["shared"]) == {"x", "y"}

    async def test_multi_target_aliases(self):
        """One name maps to multiple aliases."""
        result = build_reverse_aliases({"legacy": ("v2.a", "v2.b")})
        assert result["v2.a"] == ("legacy",)
        assert result["v2.b"] == ("legacy",)

    async def test_reverse_values_are_sorted_tuples(self):
        result = build_reverse_aliases({"z_name": ("alias",), "a_name": ("alias",)})
        # Values should be sorted tuples
        assert result["alias"] == ("a_name", "z_name")

    async def test_duplicate_handling_no_duplication(self):
        """If same pair appears via different paths, no duplicates in output."""
        alias_map = {"src": ("dst",)}
        result = build_reverse_aliases(alias_map)
        assert result["dst"].count("src") == 1

    async def test_complex_map_all_aliases_covered(self):
        alias_map = {
            "a": ("x", "y"),
            "b": ("y", "z"),
        }
        result = build_reverse_aliases(alias_map)
        assert "x" in result
        assert "y" in result
        assert "z" in result
        assert result["x"] == ("a",)
        assert set(result["y"]) == {"a", "b"}
        assert result["z"] == ("b",)

    async def test_preserves_mapping_type_input(self):
        """Accepts Mapping, not just dict."""
        from collections import OrderedDict

        alias_map = OrderedDict([("k", ("v",))])
        result = build_reverse_aliases(alias_map)
        assert result == {"v": ("k",)}


# ---------------------------------------------------------------------------
# EventV2 model edge cases
# ---------------------------------------------------------------------------


class TestEventV2Model:
    """Pydantic EventV2 model edge cases."""

    async def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError) as exc_info:
            EventV2(event_type="test", unknown_field="bad")  # type: ignore[call-arg]
        assert "extra" in str(exc_info.value).lower() or "extra_forbidden" in str(
            exc_info.value
        )

    async def test_event_type_min_length_rejects_empty(self):
        with pytest.raises(ValidationError):
            EventV2(event_type="")

    async def test_event_type_min_length_accepts_single_char(self):
        ev = EventV2(event_type="x")
        assert ev.event_type == "x"

    async def test_default_schema_version(self):
        ev = EventV2(event_type="test")
        assert ev.schema_version == "2.0.0"

    async def test_custom_schema_version(self):
        ev = EventV2(event_type="test", schema_version="3.0.0")
        assert ev.schema_version == "3.0.0"

    async def test_default_payload_empty_dict(self):
        ev = EventV2(event_type="test")
        assert ev.payload == {}

    async def test_default_emitted_at_utc(self):
        before = datetime.now(UTC)
        ev = EventV2(event_type="test")
        after = datetime.now(UTC)
        assert before <= ev.emitted_at <= after

    async def test_to_legacy_payload_merges_all_fields(self):
        ev = EventV2(event_type="scan.started", payload={"target": "example.com"})
        legacy = ev.to_legacy_payload()
        assert legacy["target"] == "example.com"
        assert legacy["schema_version"] == "2.0.0"
        assert legacy["event_type"] == "scan.started"
        assert "emitted_at" in legacy

    async def test_to_legacy_payload_emitted_at_is_isoformat(self):
        ev = EventV2(event_type="test")
        legacy = ev.to_legacy_payload()
        # Should be parseable isoformat string
        datetime.fromisoformat(legacy["emitted_at"])

    async def test_to_legacy_payload_payload_keys_override_meta(self):
        """If payload contains 'schema_version', the spread puts it first,
        then the explicit assignment overwrites it."""
        ev = EventV2(
            event_type="test",
            payload={"schema_version": "custom"},
        )
        legacy = ev.to_legacy_payload()
        # Explicit field assignment comes after **payload spread → overwrites
        assert legacy["schema_version"] == "2.0.0"


# ---------------------------------------------------------------------------
# normalize_event_payload edge cases
# ---------------------------------------------------------------------------


class TestNormalizeEventPayload:
    """Edge cases for normalize_event_payload."""

    async def test_none_payload_returns_defaults(self):
        result = normalize_event_payload("evt", None)
        assert result["schema_version"] == "2.0.0"
        assert result["event_type"] == "evt"
        assert "emitted_at" in result

    async def test_existing_schema_version_not_overwritten(self):
        result = normalize_event_payload("evt", {"schema_version": "1.0.0"})
        assert result["schema_version"] == "1.0.0"

    async def test_existing_event_type_not_overwritten(self):
        result = normalize_event_payload("evt", {"event_type": "custom_type"})
        assert result["event_type"] == "custom_type"

    async def test_existing_emitted_at_not_overwritten(self):
        ts = "2020-01-01T00:00:00+00:00"
        result = normalize_event_payload("evt", {"emitted_at": ts})
        assert result["emitted_at"] == ts

    async def test_missing_keys_added(self):
        result = normalize_event_payload("my_event", {"custom_key": "value"})
        assert result["custom_key"] == "value"
        assert result["schema_version"] == "2.0.0"
        assert result["event_type"] == "my_event"
        assert "emitted_at" in result

    async def test_empty_dict_payload_gets_defaults(self):
        result = normalize_event_payload("evt", {})
        assert result["schema_version"] == "2.0.0"
        assert result["event_type"] == "evt"
        assert "emitted_at" in result

    async def test_does_not_mutate_original_mapping(self):
        original = {"key": "val"}
        original_copy = dict(original)
        normalize_event_payload("evt", original)
        assert original == original_copy

    async def test_emitted_at_is_isoformat_string(self):
        result = normalize_event_payload("evt", None)
        # Should be parseable
        datetime.fromisoformat(result["emitted_at"])
