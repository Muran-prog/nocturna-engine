"""Edge-case tests for plugin discovery, package scanning, and import-failure handling."""

from __future__ import annotations

import importlib
import sys
import types
from typing import Any, ClassVar
from unittest.mock import MagicMock, patch

import pytest

from nocturna_engine.core.event_bus import EventBus
from nocturna_engine.core.plugin_manager import PluginManager
from nocturna_engine.exceptions import PluginRegistrationError
from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.models.finding import Finding, SeverityLevel
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class AlphaTool(BaseTool):
    name: ClassVar[str] = "alpha_tool"
    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


class BetaTool(BaseTool):
    name: ClassVar[str] = "beta_tool"
    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)
    async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# discover_plugins without package_name
# ---------------------------------------------------------------------------

async def test_discover_plugins_no_package_name():
    """discover_plugins() without a package scans all subclasses of BaseTool."""
    pm = PluginManager()
    # There will be subclasses from test doubles loaded globally
    names = pm.discover_plugins()
    assert isinstance(names, list)
    assert names == sorted(set(names))  # no duplicates, sorted


async def test_discover_plugins_returns_sorted_unique():
    pm = PluginManager()
    names = pm.discover_plugins()
    assert names == sorted(names)
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# discover_plugins with package_name
# ---------------------------------------------------------------------------

async def test_discover_plugins_valid_package():
    """A valid package should discover tools in that package."""
    pm = PluginManager()
    # nocturna_engine.interfaces has BaseTool but not concrete subclasses
    names = pm.discover_plugins("nocturna_engine.interfaces")
    assert isinstance(names, list)


async def test_discover_plugins_nonexistent_package():
    """Non-existent root package raises ModuleNotFoundError from deterministic registry."""
    pm = PluginManager()
    # The deterministic registry's _collect_module_names raises for unknown root packages
    with pytest.raises(ModuleNotFoundError):
        pm.discover_plugins("nonexistent_fake_package_xyz")


async def test_discover_plugins_package_with_no_submodules():
    """A package without __path__ should return early after root import."""
    # Create a mock module with no __path__
    fake_module = types.ModuleType("fake_no_path_pkg")
    with patch.dict(sys.modules, {"fake_no_path_pkg": fake_module}):
        pm = PluginManager()
        names = pm.discover_plugins("fake_no_path_pkg")
        assert isinstance(names, list)


# ---------------------------------------------------------------------------
# Import failure recording
# ---------------------------------------------------------------------------

async def test_import_failure_metadata_structure():
    """Each import failure should have module, reason, reason_code, error, error_type."""
    fake_root = types.ModuleType("fake_struct_pkg")
    fake_root.__path__ = ["/tmp/fake_struct_pkg"]  # type: ignore[attr-defined]
    fake_root.__name__ = "fake_struct_pkg"

    with patch.dict(sys.modules, {"fake_struct_pkg": fake_root}):
        with patch("pkgutil.walk_packages", return_value=[(None, "fake_struct_pkg.bad", False)]):
            with patch("importlib.import_module") as mock_import:
                def side_effect(name):
                    if name == "fake_struct_pkg":
                        return fake_root
                    raise ImportError("test failure")
                mock_import.side_effect = side_effect
                pm = PluginManager()
                pm.discover_plugins("fake_struct_pkg")
                report = pm.get_last_discovery_report()
                for failure in report["import_failures"]:
                    assert "module" in failure
                    assert "reason" in failure
                    assert "reason_code" in failure
                    assert "error" in failure
                    assert "error_type" in failure


async def test_import_failure_submodule_recorded():
    """When a submodule fails to import, it should be in the failure list."""
    fake_root = types.ModuleType("fake_root_pkg")
    fake_root.__path__ = ["/tmp/fake_root_pkg"]  # type: ignore[attr-defined]
    fake_root.__name__ = "fake_root_pkg"

    def fake_walk_packages(path, prefix):
        yield None, "fake_root_pkg.bad_sub", False

    with patch.dict(sys.modules, {"fake_root_pkg": fake_root}):
        with patch("pkgutil.walk_packages", side_effect=fake_walk_packages):
            with patch("importlib.import_module") as mock_import:
                def side_effect(name):
                    if name == "fake_root_pkg":
                        return fake_root
                    raise ImportError("cannot import")
                mock_import.side_effect = side_effect

                pm = PluginManager()
                pm.discover_plugins("fake_root_pkg")
                report = pm.get_last_discovery_report()
                failures = report["import_failures"]
                modules = [f["module"] for f in failures]
                assert "fake_root_pkg.bad_sub" in modules


# ---------------------------------------------------------------------------
# Strict discovery mode
# ---------------------------------------------------------------------------

async def test_strict_discovery_raises_on_import_failure():
    """With strict_plugin_discovery=True, import failures raise PluginRegistrationError."""
    fake_root = types.ModuleType("fake_strict_pkg")
    fake_root.__path__ = ["/tmp/fake_strict_pkg"]  # type: ignore[attr-defined]
    fake_root.__name__ = "fake_strict_pkg"

    with patch.dict(sys.modules, {"fake_strict_pkg": fake_root}):
        with patch("pkgutil.walk_packages", return_value=[(None, "fake_strict_pkg.bad", False)]):
            with patch("importlib.import_module") as mock_import:
                def side_effect(name):
                    if name == "fake_strict_pkg":
                        return fake_root
                    raise ImportError("strict fail")
                mock_import.side_effect = side_effect
                pm = PluginManager(feature_flags={"strict_plugin_discovery": True})
                with pytest.raises(PluginRegistrationError, match="Strict plugin discovery"):
                    pm.discover_plugins("fake_strict_pkg")


async def test_strict_discovery_via_config():
    """strict_discovery from config plugins section."""
    fake_root = types.ModuleType("fake_strict_cfg_pkg")
    fake_root.__path__ = ["/tmp/fake_strict_cfg_pkg"]  # type: ignore[attr-defined]
    fake_root.__name__ = "fake_strict_cfg_pkg"

    with patch.dict(sys.modules, {"fake_strict_cfg_pkg": fake_root}):
        with patch("pkgutil.walk_packages", return_value=[(None, "fake_strict_cfg_pkg.bad", False)]):
            with patch("importlib.import_module") as mock_import:
                def side_effect(name):
                    if name == "fake_strict_cfg_pkg":
                        return fake_root
                    raise ImportError("cfg fail")
                mock_import.side_effect = side_effect
                pm = PluginManager(config={"plugins": {"strict_discovery": True}})
                with pytest.raises(PluginRegistrationError, match="Strict plugin discovery"):
                    pm.discover_plugins("fake_strict_cfg_pkg")


async def test_nonstrict_discovery_continues_on_failure():
    """Without strict mode, submodule failures are captured but discovery continues."""
    fake_root = types.ModuleType("fake_nonstrict_pkg")
    fake_root.__path__ = ["/tmp/fake_nonstrict_pkg"]  # type: ignore[attr-defined]
    fake_root.__name__ = "fake_nonstrict_pkg"

    with patch.dict(sys.modules, {"fake_nonstrict_pkg": fake_root}):
        with patch("pkgutil.walk_packages", return_value=[(None, "fake_nonstrict_pkg.bad", False)]):
            with patch("importlib.import_module") as mock_import:
                def side_effect(name):
                    if name == "fake_nonstrict_pkg":
                        return fake_root
                    raise ImportError("submodule fail")
                mock_import.side_effect = side_effect
                pm = PluginManager(feature_flags={"strict_plugin_discovery": False})
                names = pm.discover_plugins("fake_nonstrict_pkg")
                assert isinstance(names, list)
                report = pm.get_last_discovery_report()
                assert len(report["import_failures"]) > 0
                assert report["strict"] is False


# ---------------------------------------------------------------------------
# get_last_discovery_report normalization
# ---------------------------------------------------------------------------

async def test_discovery_report_default():
    pm = PluginManager()
    report = pm.get_last_discovery_report()
    assert report["package_name"] is None
    assert report["strict"] is False
    assert report["import_failures"] == []


async def test_discovery_report_normalizes_non_mapping_failures():
    """If internal failures contain non-mapping items, they are skipped."""
    pm = PluginManager()
    # Manually inject broken data
    pm._last_discovery_report = {
        "package_name": "test",
        "strict": False,
        "import_failures": ["not a dict", 42, {"module": "ok", "error": "e"}],
    }
    report = pm.get_last_discovery_report()
    # Only the valid dict should come through
    assert len(report["import_failures"]) == 1
    assert report["import_failures"][0]["module"] == "ok"


async def test_discovery_report_populates_defaults_for_missing_keys():
    """Missing keys in failure dict should get default empty strings."""
    pm = PluginManager()
    pm._last_discovery_report = {
        "package_name": "test",
        "strict": False,
        "import_failures": [{"module": "m"}],
    }
    report = pm.get_last_discovery_report()
    f = report["import_failures"][0]
    assert f["module"] == "m"
    assert f["reason"] == "module_import_failed"
    assert f["reason_code"] == "module_import_failed"
    assert f["error"] == ""
    assert f["error_type"] == ""


# ---------------------------------------------------------------------------
# Registration during discovery
# ---------------------------------------------------------------------------

async def test_discover_skips_duplicate_registrations():
    pm = PluginManager()
    pm.register_tool_class(AlphaTool)
    # discover_plugins without package will find AlphaTool via subclasses
    names = pm.discover_plugins()
    assert "alpha_tool" in names
    # No duplicate despite pre-registration
    assert names.count("alpha_tool") <= 1


async def test_register_tool_class_source_param():
    """register_tool_class should pass source to deterministic registry."""
    pm = PluginManager()
    pm.register_tool_class(AlphaTool, source="test_source")
    reg = pm._deterministic_registry.get_registration("alpha_tool")
    assert reg is not None
    assert reg.source == "test_source"


# ---------------------------------------------------------------------------
# Legacy subclasses fallback
# ---------------------------------------------------------------------------

async def test_legacy_discovery_subclasses_fallback_flag():
    """When legacy_discovery_subclasses_fallback=True, both code paths run."""
    pm = PluginManager(feature_flags={"legacy_discovery_subclasses_fallback": True})
    names = pm.discover_plugins()
    assert isinstance(names, list)


async def test_iter_subclasses_finds_transitives():
    """_iter_subclasses should find classes through multiple levels."""

    class GrandChild(AlphaTool):
        name: ClassVar[str] = "grandchild_tool"
        async def execute(self, request: ScanRequest) -> ScanResult:
            return ScanResult(request_id=request.request_id, tool_name=self.name)
        async def parse_output(self, raw_output: Any, request: ScanRequest) -> list[Finding]:
            return []

    subs = PluginManager._iter_subclasses(BaseTool)
    class_names = [c.__name__ for c in subs]
    assert "GrandChild" in class_names
    assert "AlphaTool" in class_names


# ---------------------------------------------------------------------------
# _filter_classes_by_package
# ---------------------------------------------------------------------------

async def test_filter_classes_by_package():
    """Only classes from the given package prefix should pass."""
    result = PluginManager._filter_classes_by_package([AlphaTool, BetaTool], "tests.core.plugin_manager")
    # Both are defined in this file's module
    assert AlphaTool in result
    assert BetaTool in result


async def test_filter_classes_by_package_excludes_other():
    result = PluginManager._filter_classes_by_package([AlphaTool], "nocturna_engine.interfaces")
    assert AlphaTool not in result


# ---------------------------------------------------------------------------
# _iter_unique_classes
# ---------------------------------------------------------------------------

async def test_iter_unique_classes_deduplicates():
    result = PluginManager._iter_unique_classes([AlphaTool, BetaTool], [AlphaTool])
    assert len(result) == 2
    assert result[0] is AlphaTool
    assert result[1] is BetaTool


async def test_iter_unique_classes_preserves_order():
    result = PluginManager._iter_unique_classes([BetaTool, AlphaTool])
    assert result[0] is BetaTool
    assert result[1] is AlphaTool
