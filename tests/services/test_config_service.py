"""Comprehensive edge-case tests for ConfigService."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from nocturna_engine.exceptions import ConfigError
from nocturna_engine.services.config_service import ConfigService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def temp_dir() -> Any:
    """Create a temporary directory in the project folder and clean up after."""
    d = tempfile.mkdtemp(dir=".")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path: Path, filename: str, data: Any) -> Path:
    """Write arbitrary data as YAML to a temp file and return the path."""
    p = tmp_path / filename
    p.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return p


def _write_text(tmp_path: Path, filename: str, text: str) -> Path:
    p = tmp_path / filename
    p.write_text(text, encoding="utf-8")
    return p


def _make_service(
    config_path: str | Path | None = None,
    dotenv_path: str | Path | None = None,
    env_prefix: str = "NOCTURNA",
) -> ConfigService:
    return ConfigService(config_path=config_path, dotenv_path=dotenv_path, env_prefix=env_prefix)


# ===========================================================================
# _load_yaml edge cases
# ===========================================================================


class TestLoadYaml:
    """Tests for ConfigService._load_yaml static method."""

    def test_missing_file_raises_config_error(self, temp_dir: Path) -> None:
        missing = temp_dir / "nonexistent.yaml"
        with pytest.raises(ConfigError, match="Config file not found"):
            ConfigService._load_yaml(missing)

    def test_malformed_yaml_raises_config_error(self, temp_dir: Path) -> None:
        bad = _write_text(temp_dir, "bad.yaml", ":\n  :\n  - :\n  {{invalid")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            ConfigService._load_yaml(bad)

    def test_non_dict_yaml_raises_config_error(self, temp_dir: Path) -> None:
        """A YAML list at the top level is not a valid config."""
        list_yaml = _write_yaml(temp_dir, "list.yaml", [1, 2, 3])
        with pytest.raises(ConfigError, match="top-level mapping"):
            ConfigService._load_yaml(list_yaml)

    def test_scalar_yaml_raises_config_error(self, temp_dir: Path) -> None:
        """A scalar string at the top level is not a valid config."""
        scalar = _write_text(temp_dir, "scalar.yaml", '"just a string"')
        with pytest.raises(ConfigError, match="top-level mapping"):
            ConfigService._load_yaml(scalar)

    def test_empty_yaml_returns_empty_dict(self, temp_dir: Path) -> None:
        """An empty file (parsed as None by PyYAML) should return {}."""
        empty = _write_text(temp_dir, "empty.yaml", "")
        assert ConfigService._load_yaml(empty) == {}

    def test_valid_yaml_returns_dict(self, temp_dir: Path) -> None:
        data = {"engine": {"max_concurrency": 8}}
        p = _write_yaml(temp_dir, "ok.yaml", data)
        assert ConfigService._load_yaml(p) == data


# ===========================================================================
# _deep_merge edge cases
# ===========================================================================


class TestDeepMerge:
    """Tests for ConfigService._deep_merge static method."""

    def test_empty_base_adopts_override(self) -> None:
        assert ConfigService._deep_merge({}, {"a": 1}) == {"a": 1}

    def test_empty_override_preserves_base(self) -> None:
        assert ConfigService._deep_merge({"a": 1}, {}) == {"a": 1}

    def test_both_empty(self) -> None:
        assert ConfigService._deep_merge({}, {}) == {}

    def test_nested_dict_merge(self) -> None:
        base = {"a": {"b": 1, "c": 2}}
        over = {"a": {"c": 3, "d": 4}}
        merged = ConfigService._deep_merge(base, over)
        assert merged == {"a": {"b": 1, "c": 3, "d": 4}}

    def test_type_conflict_override_wins(self) -> None:
        """When override has a scalar but base has a dict, override wins."""
        base = {"a": {"nested": True}}
        over = {"a": "flat_string"}
        assert ConfigService._deep_merge(base, over) == {"a": "flat_string"}

    def test_type_conflict_dict_over_scalar(self) -> None:
        """When override has a dict but base has a scalar, override wins."""
        base = {"a": 42}
        over = {"a": {"nested": True}}
        assert ConfigService._deep_merge(base, over) == {"a": {"nested": True}}

    def test_deeply_nested_merge(self) -> None:
        base = {"l1": {"l2": {"l3": {"val": "old"}}}}
        over = {"l1": {"l2": {"l3": {"val": "new", "extra": True}}}}
        merged = ConfigService._deep_merge(base, over)
        assert merged["l1"]["l2"]["l3"] == {"val": "new", "extra": True}

    def test_base_not_mutated(self) -> None:
        base = {"a": {"b": 1}}
        over = {"a": {"b": 2}}
        ConfigService._deep_merge(base, over)
        assert base["a"]["b"] == 1  # original untouched

    def test_list_in_override_replaces_not_merges(self) -> None:
        base = {"tags": [1, 2]}
        over = {"tags": [3]}
        assert ConfigService._deep_merge(base, over) == {"tags": [3]}


# ===========================================================================
# _coerce_value edge cases
# ===========================================================================


class TestCoerceValue:
    """Tests for ConfigService._coerce_value static method."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("true", True),
            ("True", True),
            ("TRUE", True),
            ("false", False),
            ("False", False),
            (" true ", True),
        ],
    )
    def test_bool_coercion(self, raw: str, expected: bool) -> None:
        assert ConfigService._coerce_value(raw) is expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("null", None),
            ("none", None),
            ("Null", None),
            ("None", None),
            (" null ", None),
        ],
    )
    def test_null_coercion(self, raw: str, expected: None) -> None:
        assert ConfigService._coerce_value(raw) is expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("42", 42),
            ("-1", -1),
            ("0", 0),
        ],
    )
    def test_int_coercion(self, raw: str, expected: int) -> None:
        result = ConfigService._coerce_value(raw)
        assert result == expected
        assert isinstance(result, int)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("3.14", 3.14),
            ("-0.5", -0.5),
            ("0.0", 0.0),
        ],
    )
    def test_float_coercion(self, raw: str, expected: float) -> None:
        result = ConfigService._coerce_value(raw)
        assert result == pytest.approx(expected)
        assert isinstance(result, float)

    def test_yaml_list_coercion(self) -> None:
        assert ConfigService._coerce_value("[1, 2, 3]") == [1, 2, 3]

    def test_yaml_dict_coercion(self) -> None:
        assert ConfigService._coerce_value("{a: 1, b: 2}") == {"a": 1, "b": 2}

    def test_plain_string_passthrough(self) -> None:
        assert ConfigService._coerce_value("hello world") == "hello world"

    def test_dot_in_non_numeric_string(self) -> None:
        """A dotted value that isn't a valid float falls through to YAML/string."""
        result = ConfigService._coerce_value("not.a.number")
        # Not a float, not a list/dict, should be returned as string
        assert isinstance(result, str)

    def test_empty_string(self) -> None:
        result = ConfigService._coerce_value("")
        # empty string: lowered is "", not in bools/nulls, no dot, int("") fails,
        # yaml.safe_load("") returns None which is not dict/list, so returns ""
        assert result == ""


# ===========================================================================
# _extract_env_overrides & env integration
# ===========================================================================


class TestEnvOverrides:
    """Tests for environment variable extraction and nesting."""

    def test_single_level_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_LOGLEVEL", "DEBUG")
        svc = _make_service()
        overrides = svc._extract_env_overrides()
        assert overrides["loglevel"] == "DEBUG"

    def test_double_underscore_nesting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_ENGINE__MAX_CONCURRENCY", "8")
        svc = _make_service()
        overrides = svc._extract_env_overrides()
        assert overrides["engine"]["max_concurrency"] == 8

    def test_triple_underscore_deep_nesting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_A__B__C", "deep")
        svc = _make_service()
        overrides = svc._extract_env_overrides()
        assert overrides["a"]["b"]["c"] == "deep"

    def test_secret_prefix_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """NOCTURNA_SECRET_* vars should NOT appear in config overrides."""
        monkeypatch.setenv("NOCTURNA_SECRET_DB_PASS", "hunter2")
        svc = _make_service()
        overrides = svc._extract_env_overrides()
        assert "secret_db_pass" not in str(overrides)
        assert "secret" not in overrides

    def test_custom_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MYAPP_FOO", "bar")
        svc = _make_service(env_prefix="MYAPP")
        overrides = svc._extract_env_overrides()
        assert overrides["foo"] == "bar"

    def test_coercion_applied_to_env_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_PLUGINS__STRICT_DISCOVERY", "true")
        svc = _make_service()
        overrides = svc._extract_env_overrides()
        assert overrides["plugins"]["strict_discovery"] is True

    def test_non_matching_prefix_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTHER_VAR", "nope")
        svc = _make_service()
        overrides = svc._extract_env_overrides()
        assert "other_var" not in overrides


# ===========================================================================
# load() integration
# ===========================================================================


class TestLoad:
    """Tests for ConfigService.load() integration."""

    def test_load_defaults_only(self, monkeypatch: pytest.MonkeyPatch, temp_dir: Path) -> None:
        """Loading without user config produces defaults from default_config.yaml."""
        monkeypatch.setenv("HOME", str(temp_dir))  # prevent leaking real .env
        svc = _make_service(dotenv_path=temp_dir / ".env_nonexistent")
        config = svc.load()
        assert config["engine"]["max_concurrency"] == 4
        assert config["logging"]["level"] == "INFO"

    def test_user_yaml_overrides_defaults(self, monkeypatch: pytest.MonkeyPatch, temp_dir: Path) -> None:
        user_yaml = _write_yaml(temp_dir, "user.yaml", {"engine": {"max_concurrency": 16}})
        svc = _make_service(config_path=user_yaml, dotenv_path=temp_dir / ".env_none")
        config = svc.load()
        assert config["engine"]["max_concurrency"] == 16
        # Other defaults still present
        assert config["logging"]["level"] == "INFO"

    def test_env_overrides_user_yaml(self, monkeypatch: pytest.MonkeyPatch, temp_dir: Path) -> None:
        user_yaml = _write_yaml(temp_dir, "user.yaml", {"engine": {"max_concurrency": 16}})
        monkeypatch.setenv("NOCTURNA_ENGINE__MAX_CONCURRENCY", "32")
        svc = _make_service(config_path=user_yaml, dotenv_path=temp_dir / ".env_none")
        config = svc.load()
        assert config["engine"]["max_concurrency"] == 32

    def test_missing_user_yaml_raises(self, temp_dir: Path) -> None:
        svc = _make_service(config_path=temp_dir / "missing.yaml", dotenv_path=temp_dir / ".env_none")
        with pytest.raises(ConfigError, match="Config file not found"):
            svc.load()

    def test_dotenv_loading(self, monkeypatch: pytest.MonkeyPatch, temp_dir: Path) -> None:
        """Values from .env file should be accessible as env vars after load."""
        dotenv = _write_text(temp_dir, ".env", "NOCTURNA_ENGINE__DEFAULT_TIMEOUT_SECONDS=999")
        svc = _make_service(dotenv_path=dotenv)
        config = svc.load()
        assert config["engine"]["default_timeout_seconds"] == 999


# ===========================================================================
# get() dot-notation access
# ===========================================================================


class TestGet:
    """Tests for ConfigService.get() dot-notation accessor."""

    def test_top_level_key(self, temp_dir: Path) -> None:
        svc = _make_service(dotenv_path=temp_dir / ".env_none")
        svc.load()
        result = svc.get("logging")
        assert isinstance(result, dict)
        assert result["level"] == "INFO"

    def test_nested_key(self, temp_dir: Path) -> None:
        svc = _make_service(dotenv_path=temp_dir / ".env_none")
        svc.load()
        assert svc.get("engine.max_concurrency") == 4

    def test_deeply_nested_key(self, temp_dir: Path) -> None:
        svc = _make_service(dotenv_path=temp_dir / ".env_none")
        svc.load()
        assert svc.get("security.scope_firewall.kill_switch") is False

    def test_missing_key_returns_default(self, temp_dir: Path) -> None:
        svc = _make_service(dotenv_path=temp_dir / ".env_none")
        svc.load()
        assert svc.get("nonexistent.key", "fallback") == "fallback"

    def test_missing_key_returns_none_by_default(self, temp_dir: Path) -> None:
        svc = _make_service(dotenv_path=temp_dir / ".env_none")
        svc.load()
        assert svc.get("does.not.exist") is None

    def test_partial_path_returns_default(self, temp_dir: Path) -> None:
        """engine.max_concurrency.sub doesn't exist — int has no key 'sub'."""
        svc = _make_service(dotenv_path=temp_dir / ".env_none")
        svc.load()
        assert svc.get("engine.max_concurrency.sub", "nope") == "nope"

    def test_get_before_load_returns_default(self) -> None:
        """get() on unloaded service has empty _config, should return default."""
        svc = _make_service()
        assert svc.get("anything", 42) == 42


# ===========================================================================
# _normalize_scope_firewall_config edge cases
# ===========================================================================


class TestScopeFirewallNormalization:
    """Tests for scope_firewall normalization in _normalize_scope_firewall_config."""

    def test_none_lists_become_empty(self) -> None:
        result = ConfigService._normalize_scope_firewall_config({
            "allowlist_hosts": None,
            "allowlist_cidrs": None,
            "denylist_hosts": None,
            "denylist_cidrs": None,
        })
        assert result["allowlist_hosts"] == []
        assert result["denylist_cidrs"] == []

    def test_string_as_list_coerced(self) -> None:
        result = ConfigService._normalize_scope_firewall_config({
            "allowlist_hosts": "example.com",
        })
        assert result["allowlist_hosts"] == ["example.com"]

    def test_empty_strings_filtered(self) -> None:
        result = ConfigService._normalize_scope_firewall_config({
            "denylist_hosts": ["", "  ", "valid.com"],
        })
        assert result["denylist_hosts"] == ["valid.com"]

    def test_kill_switch_default_false(self) -> None:
        result = ConfigService._normalize_scope_firewall_config({})
        assert result["kill_switch"] is False

    def test_kill_switch_truthy(self) -> None:
        result = ConfigService._normalize_scope_firewall_config({"kill_switch": 1})
        assert result["kill_switch"] is True

    def test_non_iterable_value_returns_empty_list(self) -> None:
        """An integer where a list is expected should return []."""
        result = ConfigService._normalize_scope_firewall_config({
            "allowlist_hosts": 12345,
        })
        assert result["allowlist_hosts"] == []

    def test_tuple_and_set_accepted(self) -> None:
        result = ConfigService._normalize_scope_firewall_config({
            "allowlist_hosts": ("a.com", "b.com"),
            "denylist_hosts": {"c.com"},
        })
        assert "a.com" in result["allowlist_hosts"]
        assert "b.com" in result["allowlist_hosts"]
        assert "c.com" in result["denylist_hosts"]

    def test_mixed_types_in_list_stringified(self) -> None:
        result = ConfigService._normalize_scope_firewall_config({
            "allowlist_cidrs": [None, 42, "10.0.0.0/8"],
        })
        # None → "None" stripped → "None" (non-empty), 42 → "42"
        assert "10.0.0.0/8" in result["allowlist_cidrs"]
        assert "42" in result["allowlist_cidrs"]


class TestNormalizeRuntimeConfig:
    """Tests for _normalize_runtime_config handling missing/malformed security."""

    def test_missing_security_section(self) -> None:
        config = {"engine": {"max_concurrency": 4}}
        result = ConfigService._normalize_runtime_config(config)
        assert "security" in result
        sf = result["security"]["scope_firewall"]
        assert sf["kill_switch"] is False
        assert sf["allowlist_hosts"] == []

    def test_security_not_dict(self) -> None:
        config = {"security": "invalid"}
        result = ConfigService._normalize_runtime_config(config)
        sf = result["security"]["scope_firewall"]
        assert sf["kill_switch"] is False

    def test_scope_firewall_not_dict(self) -> None:
        config = {"security": {"scope_firewall": "bad"}}
        result = ConfigService._normalize_runtime_config(config)
        sf = result["security"]["scope_firewall"]
        assert sf["kill_switch"] is False
        assert sf["allowlist_hosts"] == []

    def test_require_ssl_defaults_to_true(self) -> None:
        """When security section has no require_ssl, it defaults to True."""
        config = {"engine": {"max_concurrency": 4}}
        result = ConfigService._normalize_runtime_config(config)
        assert result["security"]["require_ssl"] is True

    def test_require_ssl_explicit_false_preserved(self) -> None:
        """Explicit require_ssl=False should be preserved, not overwritten."""
        config = {"security": {"require_ssl": False}}
        result = ConfigService._normalize_runtime_config(config)
        assert result["security"]["require_ssl"] is False

    def test_require_ssl_explicit_true_preserved(self) -> None:
        """Explicit require_ssl=True should remain True."""
        config = {"security": {"require_ssl": True}}
        result = ConfigService._normalize_runtime_config(config)
        assert result["security"]["require_ssl"] is True

# ===========================================================================
# _set_nested edge cases
# ===========================================================================


class TestSetNested:
    """Tests for _set_nested utility."""

    def test_single_segment(self) -> None:
        d: dict[str, Any] = {}
        ConfigService._set_nested(d, ["key"], "val")
        assert d == {"key": "val"}

    def test_overwrites_non_dict_intermediate(self) -> None:
        d: dict[str, Any] = {"a": "scalar"}
        ConfigService._set_nested(d, ["a", "b"], "val")
        assert d == {"a": {"b": "val"}}
