"""Edge-case tests for PluginManager composition root, feature flags, lifecycle, and runtime config."""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, patch

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.exceptions import PluginRegistrationError
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class HealthyTool(BaseTool):
    name: ClassVar[str] = "healthy_tool"
    version: ClassVar[str] = "1.0.0"
    timeout_seconds: ClassVar[float] = 5.0
    max_retries: ClassVar[int] = 0

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name, raw_output={"ok": True})

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return [Finding(title="found", description="d", severity=SeverityLevel.INFO, tool=self.name, target="t")]


class SetupFailTool(BaseTool):
    name: ClassVar[str] = "setup_fail_tool"
    max_retries: ClassVar[int] = 0
    timeout_seconds: ClassVar[float] = 2.0

    async def setup(self) -> None:
        raise RuntimeError("setup boom")

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class NoNameTool(BaseTool):
    name: ClassVar[str] = ""

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name="")

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class TeardownFailTool(BaseTool):
    name: ClassVar[str] = "teardown_fail"
    max_retries: ClassVar[int] = 0

    async def teardown(self) -> None:
        raise RuntimeError("teardown explosion")

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


def _make_request(target: str = "example.com") -> ScanRequest:
    return ScanRequest(targets=[Target(domain=target)])


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------

async def test_register_valid_tool():
    pm = PluginManager()
    name = pm.register_tool_class(HealthyTool)
    assert name == "healthy_tool"
    assert "healthy_tool" in pm.list_registered_tools()


async def test_register_duplicate_same_class_idempotent():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    # Re-registering same class should NOT raise
    name = pm.register_tool_class(HealthyTool)
    assert name == "healthy_tool"


async def test_register_duplicate_different_class_raises():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)

    class AnotherHealthy(BaseTool):
        name: ClassVar[str] = "healthy_tool"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    import pytest
    with pytest.raises(PluginRegistrationError, match="already registered"):
        pm.register_tool_class(AnotherHealthy)


async def test_register_missing_name_raises():
    import pytest
    pm = PluginManager()
    with pytest.raises(PluginRegistrationError):
        pm.register_tool_class(NoNameTool)


async def test_register_non_basetool_raises():
    import pytest
    pm = PluginManager()
    with pytest.raises(PluginRegistrationError, match="inherit BaseTool"):
        pm.register_tool_class(int)  # type: ignore[arg-type]


async def test_register_invalid_name_special_chars():
    import pytest

    class BadChars(BaseTool):
        name: ClassVar[str] = "has spaces!!"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    pm = PluginManager()
    with pytest.raises(PluginRegistrationError):
        pm.register_tool_class(BadChars)


# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------

async def test_default_feature_flags():
    pm = PluginManager()
    flags = pm.feature_flags
    assert flags["plugin_system_v2"] is False
    assert flags["policy_fail_closed"] is True
    assert flags["event_contract_v2"] is False


async def test_custom_feature_flags_override():
    pm = PluginManager(feature_flags={"plugin_system_v2": True, "custom_flag": True})
    assert pm.is_feature_enabled("plugin_system_v2") is True
    assert pm.is_feature_enabled("custom_flag") is True


async def test_feature_flags_unknown_flag_returns_false():
    pm = PluginManager()
    assert pm.is_feature_enabled("nonexistent_flag") is False


async def test_feature_flags_normalize_values():
    pm = PluginManager(feature_flags={"plugin_system_v2": 1})  # type: ignore[dict-item]
    assert pm.is_feature_enabled("plugin_system_v2") is True


async def test_feature_flags_none_uses_defaults():
    pm = PluginManager(feature_flags=None)
    flags = pm.feature_flags
    assert "plugin_system_v2" in flags
    assert "policy_fail_closed" in flags


# ---------------------------------------------------------------------------
# apply_runtime_config
# ---------------------------------------------------------------------------

async def test_apply_runtime_config_merges_features():
    pm = PluginManager()
    assert pm.is_feature_enabled("plugin_system_v2") is False
    pm.apply_runtime_config({"features": {"plugin_system_v2": True}})
    assert pm.is_feature_enabled("plugin_system_v2") is True


async def test_apply_runtime_config_preserves_other_flags():
    pm = PluginManager(feature_flags={"custom": True})
    pm.apply_runtime_config({"features": {"plugin_system_v2": True}})
    assert pm.is_feature_enabled("custom") is True
    assert pm.is_feature_enabled("plugin_system_v2") is True


async def test_apply_runtime_config_with_no_features_key():
    pm = PluginManager()
    pm.apply_runtime_config({"something_else": 42})
    # Should not crash; flags unchanged
    assert pm.is_feature_enabled("plugin_system_v2") is False


async def test_apply_runtime_config_replaces_config():
    pm = PluginManager(config={"old_key": "old_value"})
    pm.apply_runtime_config({"new_key": "new_value"})
    assert pm._config.get("old_key") is None
    assert pm._config["new_key"] == "new_value"


async def test_apply_runtime_config_features_non_mapping_ignored():
    pm = PluginManager()
    pm.apply_runtime_config({"features": "not a dict"})
    # Should not crash; flags unchanged
    assert pm.is_feature_enabled("plugin_system_v2") is False


# ---------------------------------------------------------------------------
# Lifecycle: setup & teardown
# ---------------------------------------------------------------------------

async def test_lifecycle_initialize_plugins_empty_registry():
    pm = PluginManager()
    await pm.initialize_plugins()
    assert pm.list_active_tools() == []


async def test_lifecycle_context_manager():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    async with pm as manager:
        assert "healthy_tool" in manager.list_active_tools()
    # After exit, instances are cleared
    assert manager.list_active_tools() == []


async def test_lifecycle_setup_failure_isolated():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    pm.register_tool_class(SetupFailTool)
    await pm.initialize_plugins()
    # Healthy tool should be active; failing tool should not
    assert "healthy_tool" in pm.list_active_tools()
    assert "setup_fail_tool" not in pm.list_active_tools()


async def test_lifecycle_get_tool_setup_failure():
    pm = PluginManager()
    pm.register_tool_class(SetupFailTool)
    await pm.initialize_plugins()
    failure = pm._get_tool_setup_failure("setup_fail_tool")
    assert failure is not None
    assert "setup boom" in failure["error"]
    assert failure["reason_code"] == "tool_setup_failed"


async def test_lifecycle_teardown_failure_does_not_crash():
    pm = PluginManager()
    pm.register_tool_class(TeardownFailTool)
    await pm.initialize_plugins()
    assert "teardown_fail" in pm.list_active_tools()
    # Shutdown should not raise despite teardown failure
    await pm.shutdown_plugins()
    assert pm.list_active_tools() == []


async def test_lifecycle_double_init_is_idempotent():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    await pm.initialize_plugins()
    tool1 = pm.get_tool("healthy_tool")
    await pm.initialize_plugins()
    tool2 = pm.get_tool("healthy_tool")
    assert tool1 is tool2


# ---------------------------------------------------------------------------
# list_registered_tools / list_active_tools / get_tool
# ---------------------------------------------------------------------------

async def test_list_registered_tools_sorted():
    pm = PluginManager()

    class AaaTool(BaseTool):
        name: ClassVar[str] = "aaa_tool"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    class ZzzTool(BaseTool):
        name: ClassVar[str] = "zzz_tool"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    pm.register_tool_class(ZzzTool)
    pm.register_tool_class(AaaTool)
    tools = pm.list_registered_tools()
    assert tools == ["aaa_tool", "zzz_tool"]


async def test_get_tool_returns_none_before_init():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    assert pm.get_tool("healthy_tool") is None


async def test_get_tool_returns_instance_after_init():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    await pm.initialize_plugins()
    tool = pm.get_tool("healthy_tool")
    assert tool is not None
    assert isinstance(tool, HealthyTool)


async def test_get_tool_nonexistent_returns_none():
    pm = PluginManager()
    assert pm.get_tool("ghost") is None


# ---------------------------------------------------------------------------
# build_policy_result / evaluate_manifest_payload
# ---------------------------------------------------------------------------

async def test_build_policy_result_default():
    pm = PluginManager()
    result = pm.build_policy_result()
    assert result.valid is True
    assert result.policy.allow_network is False


async def test_build_policy_result_fail_closed_invalid_payload():
    pm = PluginManager()
    result = pm.build_policy_result({"max_timeout_seconds": -999}, fail_closed=True)
    assert result.valid is False
    assert result.reason_code == "policy_invalid"


async def test_build_policy_result_fail_open_invalid_payload():
    pm = PluginManager()
    result = pm.build_policy_result({"max_timeout_seconds": -999}, fail_closed=False)
    # Fail-open: valid is True but reason_code is policy_invalid
    assert result.valid is True
    assert result.reason_code == "policy_invalid"


async def test_build_policy_result_valid_override():
    pm = PluginManager()
    result = pm.build_policy_result({"allow_network": False})
    assert result.valid is True
    assert result.policy.allow_network is False


async def test_evaluate_manifest_payload_denied():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    desc = pm.describe_tool("healthy_tool")
    assert desc is not None
    policy = pm.build_policy_result({"allow_network": False}).policy
    # HealthyTool requires no network by default, so it should be allowed
    decision = pm.evaluate_manifest_payload(desc, policy)
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# describe_tool / describe_all_tools
# ---------------------------------------------------------------------------

async def test_describe_tool_returns_none_for_unknown():
    pm = PluginManager()
    assert pm.describe_tool("ghost") is None


async def test_describe_tool_returns_manifest():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    desc = pm.describe_tool("healthy_tool")
    assert desc is not None
    assert desc["id"] == "healthy_tool"
    assert desc["version"] == "1.0.0"


async def test_describe_all_tools_machine_readable():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    catalog = pm.describe_all_tools(machine_readable=True)
    assert "healthy_tool" in catalog


async def test_describe_all_tools_human_readable():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    catalog = pm.describe_all_tools(machine_readable=False)
    assert "plugins" in catalog


async def test_describe_tool_include_schema():
    pm = PluginManager()
    pm.register_tool_class(HealthyTool)
    desc = pm.describe_tool("healthy_tool", include_schema=True)
    assert desc is not None
    # Should have implementation section
    assert "implementation" in desc
