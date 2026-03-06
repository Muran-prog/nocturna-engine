"""Configuration loading service.

Configuration is merged from default YAML, optional user YAML, `.env`, and
environment variables. Later sources override earlier ones.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from nocturna_engine.exceptions import ConfigError


class ConfigService:
    """Load and provide merged runtime configuration."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        dotenv_path: str | Path | None = None,
        env_prefix: str = "NOCTURNA",
    ) -> None:
        """Initialize service.

        Args:
            config_path: Optional user YAML path.
            dotenv_path: Optional `.env` path.
            env_prefix: Prefix for environment overrides.
        """

        self._config_path = Path(config_path) if config_path is not None else None
        self._dotenv_path = Path(dotenv_path) if dotenv_path is not None else None
        self._env_prefix = env_prefix
        self._config: dict[str, Any] = {}

    def load(self) -> dict[str, Any]:
        """Load and merge configuration sources.

        Returns:
            dict[str, Any]: Final merged config.

        Raises:
            ConfigError: If files are unreadable or malformed.
        """

        if self._dotenv_path is not None:
            load_dotenv(dotenv_path=self._dotenv_path, override=False)
        else:
            load_dotenv(override=False)

        default_path = Path(__file__).resolve().parents[1] / "config" / "default_config.yaml"
        merged = self._deep_merge({}, self._load_yaml(default_path))

        if self._config_path is not None:
            merged = self._deep_merge(merged, self._load_yaml(self._config_path))

        env_overrides = self._extract_env_overrides()
        merged = self._deep_merge(merged, env_overrides)
        self._config = self._normalize_runtime_config(merged)
        return dict(self._config)

    def get(self, key: str, default: Any = None) -> Any:
        """Read value from loaded config using dot notation.

        Args:
            key: Dotted key path, for example `engine.max_concurrency`.
            default: Default value when key is absent.

        Returns:
            Any: Config value or default.
        """

        cursor: Any = self._config
        for part in key.split("."):
            if not isinstance(cursor, dict) or part not in cursor:
                return default
            cursor = cursor[part]
        return cursor

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        """Load one YAML file into a dictionary.

        Args:
            path: YAML file path.

        Returns:
            dict[str, Any]: Parsed YAML object.

        Raises:
            ConfigError: If file does not exist or cannot be parsed.
        """

        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ConfigError(f"Config file must contain a top-level mapping: {path}")
        return payload

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        """Merge dictionaries recursively.

        Args:
            base: Base dictionary.
            override: Override dictionary.

        Returns:
            dict[str, Any]: Merged dictionary.
        """

        result = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = ConfigService._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    @classmethod
    def _normalize_runtime_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        """Apply schema-safe defaults for optional security sections."""

        normalized = dict(config)
        security_value = normalized.get("security")
        security = dict(security_value) if isinstance(security_value, dict) else {}
        scope_firewall_value = security.get("scope_firewall")
        scope_firewall = (
            dict(scope_firewall_value)
            if isinstance(scope_firewall_value, dict)
            else {}
        )
        security.setdefault("require_ssl", True)
        security["scope_firewall"] = cls._normalize_scope_firewall_config(scope_firewall)
        normalized["security"] = security
        return normalized

    @staticmethod
    def _normalize_scope_firewall_config(scope_firewall: dict[str, Any]) -> dict[str, Any]:
        """Normalize scope firewall rule types with backward-compatible defaults."""

        def _coerce_str_list(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                values: list[Any] = [value]
            elif isinstance(value, list | tuple | set):
                values = list(value)
            else:
                return []
            normalized: list[str] = []
            for item in values:
                candidate = str(item).strip()
                if candidate:
                    normalized.append(candidate)
            return normalized

        return {
            "kill_switch": bool(scope_firewall.get("kill_switch", False)),
            "allowlist_hosts": _coerce_str_list(scope_firewall.get("allowlist_hosts")),
            "allowlist_cidrs": _coerce_str_list(scope_firewall.get("allowlist_cidrs")),
            "denylist_hosts": _coerce_str_list(scope_firewall.get("denylist_hosts")),
            "denylist_cidrs": _coerce_str_list(scope_firewall.get("denylist_cidrs")),
        }

    def _extract_env_overrides(self) -> dict[str, Any]:
        """Build nested overrides from prefixed environment variables.

        Environment key format:
            `NOCTURNA_ENGINE__MAX_CONCURRENCY=8`

        Returns:
            dict[str, Any]: Nested override object.
        """

        prefix = f"{self._env_prefix}_"
        result: dict[str, Any] = {}
        for env_name, raw_value in os.environ.items():
            if not env_name.startswith(prefix):
                continue
            if env_name.startswith(f"{self._env_prefix}_SECRET_"):
                continue
            key_path = env_name[len(prefix) :].lower().split("__")
            self._set_nested(result, key_path, self._coerce_value(raw_value))
        return result

    @staticmethod
    def _set_nested(data: dict[str, Any], path: list[str], value: Any) -> None:
        """Set value in a nested dictionary path.

        Args:
            data: Target dictionary.
            path: Key path segments.
            value: Value to assign.
        """

        cursor = data
        for key in path[:-1]:
            if key not in cursor or not isinstance(cursor[key], dict):
                cursor[key] = {}
            cursor = cursor[key]
        cursor[path[-1]] = value

    @staticmethod
    def _coerce_value(value: str) -> Any:
        """Coerce string env values into primitive Python types.

        Args:
            value: Raw string value.

        Returns:
            Any: Parsed bool/int/float/list/dict or original string.
        """

        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
        if lowered in {"null", "none"}:
            return None
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass
        try:
            parsed_yaml = yaml.safe_load(value)
            if isinstance(parsed_yaml, (dict, list)):
                return parsed_yaml
        except yaml.YAMLError:
            return value
        return value
