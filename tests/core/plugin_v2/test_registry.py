"""Edge-case tests for deterministic plugin registry, manifest building, contracts, events, health, cache, reliability, legacy adapter."""

from __future__ import annotations

import asyncio
import time
from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest
import structlog

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_v2.cache import ScanResultCache, build_result_fingerprint
from nocturna_engine.core.plugin_v2.contracts import (
    BaseToolV2,
    CapabilityDescriptor,
    CompatibilityInfo,
    EnvironmentSecretAccessor,
    ExecutionRequirements,
    HealthProfile,
    InMemoryMetricsCollector,
    InMemoryRuntimeCache,
    LocalTempStorageProvider,
    PluginManifest,
    PluginRuntimeContext,
)
from nocturna_engine.core.plugin_v2.events import (
    DEFAULT_EVENT_ALIASES,
    build_reverse_aliases,
    normalize_event_payload,
)
from nocturna_engine.core.plugin_v2.health import PluginHealthStatus, PreflightHealthOrchestrator
from nocturna_engine.core.plugin_v2.legacy_adapter import LegacyToolAdapter
from nocturna_engine.core.plugin_v2.registry import (
    DeterministicPluginRegistry,
    PluginRegistration,
    build_manifest_from_tool_class,
    declare_plugin,
)
from nocturna_engine.core.plugin_v2.reliability import CircuitBreakerRegistry, CircuitState
from nocturna_engine.exceptions import PluginRegistrationError
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class SimpleTool(BaseTool):
    name: ClassVar[str] = "simple_tool"
    version: ClassVar[str] = "2.0.0"
    timeout_seconds: ClassVar[float] = 30.0
    supported_phases: ClassVar[tuple[str, ...]] = ("recon", "scanning")
    supported_target_types: ClassVar[tuple[str, ...]] = ("domain", "ip")
    capabilities: ClassVar[tuple[dict[str, Any], ...]] = (
        {"name": "web_scan", "category": "recon", "tags": ("http",), "coverage_hint": 0.8},
    )

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={"ok": True})

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return [Finding(title="test finding", description="test description here", severity=SeverityLevel.INFO, tool=self.name, target="target")]


class BinaryTool(BaseTool):
    name: ClassVar[str] = "binary_tool"
    binary_name: ClassVar[str] = "mytool"
    requires_network: ClassVar[bool] = True

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class InvalidNameRegistryTool(BaseTool):
    name: ClassVar[str] = "has spaces!!"
    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class DeprecatedTool(BaseTool):
    name: ClassVar[str] = "deprecated_tool"
    deprecated: ClassVar[bool] = True
    deprecation_message: ClassVar[str] = "Use new_tool instead"
    replacement_plugin_id: ClassVar[str] = "new_tool"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class V2Tool(BaseToolV2):
    name: ClassVar[str] = "v2_tool"
    version: ClassVar[str] = "3.0.0"

    async def execute_v2(self, request: ScanRequest, context: PluginRuntimeContext) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={"v2": True})


def _req(target: str = "example.com") -> ScanRequest:
    return ScanRequest(targets=[Target(domain=target)])


def _logger():
    return structlog.get_logger("test")


# ---------------------------------------------------------------------------
# DeterministicPluginRegistry
# ---------------------------------------------------------------------------

async def test_registry_register_and_get():
    reg = DeterministicPluginRegistry(logger=_logger())
    registration = reg.register(SimpleTool)
    assert registration.tool_class is SimpleTool
    assert registration.manifest.id == "simple_tool"
    retrieved = reg.get_registration("simple_tool")
    assert retrieved is registration


async def test_registry_duplicate_same_class_idempotent():
    reg = DeterministicPluginRegistry(logger=_logger())
    reg.register(SimpleTool)
    reg.register(SimpleTool)  # Should not raise


async def test_registry_duplicate_different_class_raises():
    reg = DeterministicPluginRegistry(logger=_logger())
    reg.register(SimpleTool)

    class AnotherSimple(BaseTool):
        name: ClassVar[str] = "simple_tool"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    with pytest.raises(PluginRegistrationError, match="already registered"):
        reg.register(AnotherSimple)


async def test_registry_invalid_name_raises():
    reg = DeterministicPluginRegistry(logger=_logger())
    with pytest.raises(PluginRegistrationError):
        reg.register(InvalidNameRegistryTool)


async def test_registry_deterministic_ordering():
    """list_registered_names should return sorted names."""
    reg = DeterministicPluginRegistry(logger=_logger())

    class ZTool(BaseTool):
        name: ClassVar[str] = "z_tool"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    class ATool(BaseTool):
        name: ClassVar[str] = "a_tool"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    reg.register(ZTool)
    reg.register(ATool)
    names = reg.list_registered_names()
    assert names == sorted(names)


async def test_registry_get_nonexistent():
    reg = DeterministicPluginRegistry(logger=_logger())
    assert reg.get_registration("ghost") is None


async def test_registry_describe_none_for_unknown():
    reg = DeterministicPluginRegistry(logger=_logger())
    assert reg.describe("ghost") is None


async def test_registry_describe_includes_implementation():
    reg = DeterministicPluginRegistry(logger=_logger())
    reg.register(SimpleTool)
    desc = reg.describe("simple_tool")
    assert desc is not None
    assert "implementation" in desc
    assert desc["implementation"]["class_name"] == "SimpleTool"


async def test_registry_describe_all_machine_readable():
    reg = DeterministicPluginRegistry(logger=_logger())
    reg.register(SimpleTool)
    catalog = reg.describe_all(machine_readable=True)
    assert "simple_tool" in catalog


async def test_registry_describe_all_human_readable():
    reg = DeterministicPluginRegistry(logger=_logger())
    reg.register(SimpleTool)
    catalog = reg.describe_all(machine_readable=False)
    assert "plugins" in catalog
    assert any(p["name"] == "simple_tool" for p in catalog["plugins"])


# ---------------------------------------------------------------------------
# build_manifest_from_tool_class
# ---------------------------------------------------------------------------

async def test_manifest_basic_attributes():
    manifest = build_manifest_from_tool_class(SimpleTool)
    assert manifest.id == "simple_tool"
    assert manifest.version == "2.0.0"
    assert "domain" in manifest.supported_targets
    assert "recon" in manifest.supported_phases


async def test_manifest_binary_tool_requirements():
    manifest = build_manifest_from_tool_class(BinaryTool)
    assert manifest.execution_requirements.subprocess is True
    assert manifest.execution_requirements.network is True
    assert "mytool" in manifest.execution_requirements.required_binaries


async def test_manifest_deprecated_tool():
    manifest = build_manifest_from_tool_class(DeprecatedTool)
    assert manifest.compatibility.deprecated is True
    assert manifest.compatibility.deprecation_message == "Use new_tool instead"
    assert manifest.compatibility.replacement_plugin_id == "new_tool"


async def test_manifest_capabilities_from_dict():
    manifest = build_manifest_from_tool_class(SimpleTool)
    assert len(manifest.capabilities) > 0
    assert manifest.capabilities[0].name == "web_scan"


async def test_manifest_capabilities_from_phases():
    """When no capabilities but supported_phases, capabilities are built from phases."""
    class PhaseOnly(BaseTool):
        name: ClassVar[str] = "phase_only"
        supported_phases: ClassVar[tuple[str, ...]] = ("recon", "analysis")
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    manifest = build_manifest_from_tool_class(PhaseOnly)
    cap_names = {c.name for c in manifest.capabilities}
    assert "recon" in cap_names or "analysis" in cap_names


async def test_manifest_explicit_manifest():
    """Tools with __plugin_manifest__ use the explicit manifest."""
    explicit = PluginManifest(id="custom_id", display_name="Custom", version="9.9.9")

    @declare_plugin(manifest=explicit)
    class CustomTool(BaseTool):
        name: ClassVar[str] = "custom_id"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    manifest = build_manifest_from_tool_class(CustomTool)
    assert manifest.id == "custom_id"
    assert manifest.version == "9.9.9"


async def test_manifest_normalizes_id_lowercase():
    class UpperTool(BaseTool):
        name: ClassVar[str] = "UPPER_TOOL"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    manifest = build_manifest_from_tool_class(UpperTool)
    assert manifest.id == "upper_tool"


# ---------------------------------------------------------------------------
# PluginManifest model
# ---------------------------------------------------------------------------

async def test_manifest_machine_readable():
    manifest = PluginManifest(id="test", display_name="Test", version="1.0")
    data = manifest.machine_readable(include_schema=True)
    assert "id" in data
    assert "option_schema" in data


async def test_manifest_machine_readable_no_schema():
    manifest = PluginManifest(id="test", display_name="Test", version="1.0")
    data = manifest.machine_readable(include_schema=False)
    assert "option_schema" not in data


# ---------------------------------------------------------------------------
# Circuit breaker registry
# ---------------------------------------------------------------------------

async def test_circuit_breaker_initially_not_quarantined():
    cb = CircuitBreakerRegistry()
    assert cb.is_quarantined("tool_a") is False
    assert cb.quarantine_reason("tool_a") is None


async def test_circuit_breaker_record_success_resets():
    cb = CircuitBreakerRegistry()
    cb.record_failure("tool_a", threshold=3, quarantine_seconds=60, error_message="e")
    cb.record_success("tool_a")
    assert cb.is_quarantined("tool_a") is False


async def test_circuit_breaker_threshold_triggers_quarantine():
    cb = CircuitBreakerRegistry()
    for i in range(3):
        result = cb.record_failure("tool_a", threshold=3, quarantine_seconds=60, error_message=f"error {i}")
    assert result is True
    assert cb.is_quarantined("tool_a") is True
    reason = cb.quarantine_reason("tool_a")
    assert reason is not None
    assert "circuit_open" in reason


async def test_circuit_breaker_below_threshold_not_quarantined():
    cb = CircuitBreakerRegistry()
    cb.record_failure("tool_a", threshold=3, quarantine_seconds=60, error_message="e1")
    cb.record_failure("tool_a", threshold=3, quarantine_seconds=60, error_message="e2")
    assert cb.is_quarantined("tool_a") is False


async def test_circuit_breaker_quarantine_expires():
    """When quarantine time passes, tool is no longer quarantined."""
    cb = CircuitBreakerRegistry()
    for i in range(3):
        cb.record_failure("tool_a", threshold=3, quarantine_seconds=0.01, error_message="e")
    assert cb.is_quarantined("tool_a") is True
    await asyncio.sleep(0.05)
    assert cb.is_quarantined("tool_a") is False


# ---------------------------------------------------------------------------
# InMemoryRuntimeCache
# ---------------------------------------------------------------------------

async def test_runtime_cache_set_get():
    cache = InMemoryRuntimeCache()
    await cache.set("key1", {"value": 42})
    result = await cache.get("key1")
    assert result == {"value": 42}


async def test_runtime_cache_get_missing():
    cache = InMemoryRuntimeCache()
    assert await cache.get("nonexistent") is None


async def test_runtime_cache_delete():
    cache = InMemoryRuntimeCache()
    await cache.set("key1", "hello")
    await cache.delete("key1")
    assert await cache.get("key1") is None


async def test_runtime_cache_ttl_expiry():
    cache = InMemoryRuntimeCache()
    await cache.set("key1", "value", ttl_seconds=0.01)
    await asyncio.sleep(0.05)
    assert await cache.get("key1") is None


async def test_runtime_cache_ttl_not_expired():
    cache = InMemoryRuntimeCache()
    await cache.set("key1", "value", ttl_seconds=10.0)
    assert await cache.get("key1") == "value"


# ---------------------------------------------------------------------------
# ScanResultCache
# ---------------------------------------------------------------------------

async def test_scan_result_cache_hit_miss():
    cache = ScanResultCache(default_ttl_seconds=300.0)
    result = ScanResult(request_id="req1", tool_name="t")
    await cache.set("fp1", result)
    cached = await cache.get("fp1")
    assert cached is not None
    assert cached.request_id == "req1"
    assert cache.metrics["cache_hit"] == 1


async def test_scan_result_cache_miss():
    cache = ScanResultCache()
    assert await cache.get("miss_key") is None
    assert cache.metrics["cache_miss"] == 1


async def test_scan_result_cache_eviction_by_ttl():
    cache = ScanResultCache(default_ttl_seconds=0.01)
    await cache.set("fp1", ScanResult(request_id="r", tool_name="t"))
    await asyncio.sleep(0.05)
    assert await cache.get("fp1") is None


async def test_scan_result_cache_lru_eviction():
    cache = ScanResultCache(max_size=2, default_ttl_seconds=None)
    await cache.set("a", ScanResult(request_id="1", tool_name="t"))
    await cache.set("b", ScanResult(request_id="2", tool_name="t"))
    await cache.set("c", ScanResult(request_id="3", tool_name="t"))
    # 'a' should be evicted
    assert await cache.get("a") is None
    assert await cache.get("b") is not None
    assert await cache.get("c") is not None


async def test_scan_result_cache_max_size_validation():
    with pytest.raises(ValueError, match="max_size"):
        ScanResultCache(max_size=0)


async def test_scan_result_cache_negative_ttl_validation():
    with pytest.raises(ValueError, match="default_ttl_seconds"):
        ScanResultCache(default_ttl_seconds=-1.0)


async def test_scan_result_cache_clear():
    cache = ScanResultCache()
    await cache.set("x", ScanResult(request_id="r", tool_name="t"))
    await cache.clear()
    assert await cache.get("x") is None


async def test_build_result_fingerprint_deterministic():
    req = _req()
    fp1 = build_result_fingerprint(request=req, tool_name="t", tool_version="1.0", policy_signature={"a": 1})
    fp2 = build_result_fingerprint(request=req, tool_name="t", tool_version="1.0", policy_signature={"a": 1})
    assert fp1 == fp2


async def test_build_result_fingerprint_differs_with_tool():
    req = _req()
    fp1 = build_result_fingerprint(request=req, tool_name="t1", tool_version="1.0", policy_signature={})
    fp2 = build_result_fingerprint(request=req, tool_name="t2", tool_version="1.0", policy_signature={})
    assert fp1 != fp2


# ---------------------------------------------------------------------------
# Health check orchestrator
# ---------------------------------------------------------------------------

async def test_health_orchestrator_healthy_tool():
    logger = _logger()
    orch = PreflightHealthOrchestrator(logger=logger)

    async def resolver(tool_name: str):
        mock = MagicMock()
        mock.manifest = PluginManifest(id=tool_name, display_name=tool_name, version="1.0")
        mock.health_check = AsyncMock(return_value=True)
        return mock

    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=logger, config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    result = await orch.run(tool_names=["tool_a"], adapter_resolver=resolver, context=ctx, concurrency_limit=2)
    assert result["tool_a"].healthy is True


async def test_health_orchestrator_failing_tool():
    logger = _logger()
    orch = PreflightHealthOrchestrator(logger=logger)

    async def resolver(tool_name: str):
        mock = MagicMock()
        mock.manifest = PluginManifest(id=tool_name, display_name=tool_name, version="1.0")
        mock.health_check = AsyncMock(return_value=False)
        return mock

    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=logger, config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    result = await orch.run(tool_names=["tool_a"], adapter_resolver=resolver, context=ctx, concurrency_limit=2)
    assert result["tool_a"].healthy is False


async def test_health_orchestrator_unavailable_adapter():
    logger = _logger()
    orch = PreflightHealthOrchestrator(logger=logger)

    async def resolver(tool_name: str):
        return None

    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=logger, config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    result = await orch.run(tool_names=["ghost"], adapter_resolver=resolver, context=ctx, concurrency_limit=2)
    assert result["ghost"].healthy is False
    assert result["ghost"].reason == "unavailable"


async def test_health_orchestrator_exception_handling():
    logger = _logger()
    orch = PreflightHealthOrchestrator(logger=logger)

    async def resolver(tool_name: str):
        mock = MagicMock()
        mock.manifest = PluginManifest(id=tool_name, display_name=tool_name, version="1.0")
        mock.health_check = AsyncMock(side_effect=RuntimeError("boom"))
        return mock

    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=logger, config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    result = await orch.run(tool_names=["tool_a"], adapter_resolver=resolver, context=ctx, concurrency_limit=2)
    assert result["tool_a"].healthy is False
    assert "boom" in (result["tool_a"].reason or "")


# ---------------------------------------------------------------------------
# Legacy adapter
# ---------------------------------------------------------------------------

async def test_legacy_adapter_execute():
    tool = SimpleTool()
    manifest = build_manifest_from_tool_class(SimpleTool)
    adapter = LegacyToolAdapter(tool_name="simple_tool", tool=tool, manifest=manifest)
    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=_logger(), config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    result = await adapter.execute(_req(), ctx)
    assert result.tool_name == "simple_tool"
    assert result.success is True


async def test_legacy_adapter_health_check_no_method():
    tool = SimpleTool()
    manifest = build_manifest_from_tool_class(SimpleTool)
    adapter = LegacyToolAdapter(tool_name="simple_tool", tool=tool, manifest=manifest)
    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=_logger(), config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    assert await adapter.health_check(ctx) is True


async def test_legacy_adapter_health_check_with_method():
    tool = SimpleTool()
    tool.health_check = AsyncMock(return_value=False)  # type: ignore[attr-defined]
    manifest = build_manifest_from_tool_class(SimpleTool)
    adapter = LegacyToolAdapter(tool_name="simple_tool", tool=tool, manifest=manifest)
    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=_logger(), config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    assert await adapter.health_check(ctx) is False


async def test_legacy_adapter_bind_context():
    """BaseToolV2 gets runtime context bound during adapter execute."""
    tool = V2Tool()
    manifest = build_manifest_from_tool_class(V2Tool)
    adapter = LegacyToolAdapter(tool_name="v2_tool", tool=tool, manifest=manifest)
    ctx = PluginRuntimeContext(
        event_bus=EventBus(), logger=_logger(), config={},
        secrets=EnvironmentSecretAccessor(), cache=InMemoryRuntimeCache(),
        cancellation_token=asyncio.Event(), storage=LocalTempStorageProvider(),
        metrics=InMemoryMetricsCollector(),
    )
    await adapter.execute(_req(), ctx)
    assert tool.runtime_context is ctx


# ---------------------------------------------------------------------------
# InMemoryMetricsCollector
# ---------------------------------------------------------------------------

async def test_metrics_increment():
    m = InMemoryMetricsCollector()
    m.increment("counter_a")
    m.increment("counter_a", value=5)
    assert m.counters["counter_a"] == 6


async def test_metrics_observe():
    m = InMemoryMetricsCollector()
    m.observe("latency", 1.5)
    m.observe("latency", 2.0)
    assert m.histograms["latency"] == [1.5, 2.0]


# ---------------------------------------------------------------------------
# EnvironmentSecretAccessor
# ---------------------------------------------------------------------------

async def test_secret_accessor_missing_returns_default():
    accessor = EnvironmentSecretAccessor()
    assert accessor.get_secret("NONEXISTENT_KEY_12345") is None
    assert accessor.get_secret("NONEXISTENT_KEY_12345", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# Events module
# ---------------------------------------------------------------------------

async def test_event_aliases_exist():
    assert isinstance(DEFAULT_EVENT_ALIASES, dict)
    assert len(DEFAULT_EVENT_ALIASES) > 0


async def test_build_reverse_aliases():
    aliases = {"new_name": ("old_name",)}
    reverse = build_reverse_aliases(aliases)
    assert "old_name" in reverse
    assert "new_name" in reverse["old_name"]


# ---------------------------------------------------------------------------
# PluginHealthStatus
# ---------------------------------------------------------------------------

async def test_health_status_defaults():
    status = PluginHealthStatus(plugin_name="test", healthy=True)
    assert status.reason is None
    assert status.latency_ms == 0


async def test_health_status_with_reason():
    status = PluginHealthStatus(plugin_name="test", healthy=False, reason="timeout", latency_ms=500)
    assert status.reason == "timeout"
    assert status.latency_ms == 500
