"""Comprehensive edge-case tests for SecretService."""

from __future__ import annotations

from types import ModuleType
from typing import Any
from unittest.mock import MagicMock

import pytest

from nocturna_engine.exceptions import SecretNotFoundError
from nocturna_engine.services.secret_service import SecretService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service(
    env_prefix: str = "NOCTURNA_SECRET",
    keyring_service: str = "nocturna_engine",
) -> SecretService:
    return SecretService(env_prefix=env_prefix, keyring_service=keyring_service)


# ===========================================================================
# get_secret: env var resolution
# ===========================================================================


class TestGetSecretEnvVars:
    """Tests for env-var based secret retrieval."""

    def test_prefixed_env_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_SECRET_DB_PASSWORD", "s3cret")
        svc = _make_service()
        assert svc.get_secret("db_password") == "s3cret"

    def test_unprefixed_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If prefixed var is missing, the normalized name itself is checked."""
        monkeypatch.setenv("DB_PASSWORD", "fallback_val")
        svc = _make_service()
        assert svc.get_secret("db_password") == "fallback_val"

    def test_prefixed_takes_priority_over_unprefixed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_SECRET_API_KEY", "from_prefix")
        monkeypatch.setenv("API_KEY", "from_bare")
        svc = _make_service()
        assert svc.get_secret("api_key") == "from_prefix"

    def test_case_normalization(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Name is uppercased before lookup."""
        monkeypatch.setenv("NOCTURNA_SECRET_MY_TOKEN", "tok")
        svc = _make_service()
        assert svc.get_secret("my_token") == "tok"
        assert svc.get_secret("My_Token") == "tok"
        assert svc.get_secret("MY_TOKEN") == "tok"

    def test_hyphen_to_underscore_normalization(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_SECRET_MY_API_KEY", "hval")
        svc = _make_service()
        assert svc.get_secret("my-api-key") == "hval"

    def test_whitespace_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_SECRET_FOO", "bar")
        svc = _make_service()
        assert svc.get_secret("  foo  ") == "bar"

    def test_custom_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MYAPP_TOKEN", "custom")
        svc = _make_service(env_prefix="MYAPP")
        assert svc.get_secret("token") == "custom"


# ===========================================================================
# get_secret: required / optional
# ===========================================================================


class TestGetSecretRequired:
    """Tests for required=True / required=False behavior."""

    def test_required_true_raises_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Ensure neither prefixed nor bare var exists
        monkeypatch.delenv("NOCTURNA_SECRET_MISSING", raising=False)
        monkeypatch.delenv("MISSING", raising=False)
        svc = _make_service()
        with pytest.raises(SecretNotFoundError, match="Required secret not found"):
            svc.get_secret("missing", required=True)

    def test_required_false_returns_none_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NOCTURNA_SECRET_NOPE", raising=False)
        monkeypatch.delenv("NOPE", raising=False)
        svc = _make_service()
        assert svc.get_secret("nope", required=False) is None

    def test_required_default_is_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NOCTURNA_SECRET_X", raising=False)
        monkeypatch.delenv("X", raising=False)
        svc = _make_service()
        with pytest.raises(SecretNotFoundError):
            svc.get_secret("x")

    def test_empty_string_env_treated_as_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """os.getenv returns '' but the `if value:` check treats it as falsy."""
        monkeypatch.setenv("NOCTURNA_SECRET_EMPTY", "")
        monkeypatch.delenv("EMPTY", raising=False)
        svc = _make_service()
        assert svc.get_secret("empty", required=False) is None


# ===========================================================================
# get_secret: keyring fallback
# ===========================================================================


class TestGetSecretKeyring:
    """Tests for keyring fallback behavior."""

    def test_keyring_used_when_env_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NOCTURNA_SECRET_KR_SECRET", raising=False)
        monkeypatch.delenv("KR_SECRET", raising=False)

        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = "from_keyring"
        monkeypatch.setattr("nocturna_engine.services.secret_service.SecretService._get_from_keyring",
                            lambda self, name: mock_keyring.get_password("nocturna_engine", name))
        svc = _make_service()
        assert svc.get_secret("kr_secret") == "from_keyring"

    def test_keyring_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NOCTURNA_SECRET_NO_KR", raising=False)
        monkeypatch.delenv("NO_KR", raising=False)

        monkeypatch.setattr("nocturna_engine.services.secret_service.SecretService._get_from_keyring",
                            lambda self, name: None)
        svc = _make_service()
        assert svc.get_secret("no_kr", required=False) is None

    def test_keyring_import_error_graceful(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When keyring is not installed, _get_from_keyring returns None."""
        monkeypatch.delenv("NOCTURNA_SECRET_NO_KR", raising=False)
        monkeypatch.delenv("NO_KR", raising=False)

        import builtins
        real_import = builtins.__import__

        def mock_import(name: str, *args: Any, **kwargs: Any) -> ModuleType:
            if name == "keyring":
                raise ImportError("No module named 'keyring'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        svc = _make_service()
        # Should not raise, just returns None
        assert svc.get_secret("no_kr", required=False) is None

    def test_keyring_empty_string_treated_as_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Keyring returning '' is falsy, so should not be used."""
        monkeypatch.delenv("NOCTURNA_SECRET_KR_EMPTY", raising=False)
        monkeypatch.delenv("KR_EMPTY", raising=False)

        monkeypatch.setattr("nocturna_engine.services.secret_service.SecretService._get_from_keyring",
                            lambda self, name: "")
        svc = _make_service()
        assert svc.get_secret("kr_empty", required=False) is None

    def test_env_var_takes_priority_over_keyring(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NOCTURNA_SECRET_PRIO", "env_wins")
        monkeypatch.setattr("nocturna_engine.services.secret_service.SecretService._get_from_keyring",
                            lambda self, name: "keyring_loses")
        svc = _make_service()
        assert svc.get_secret("prio") == "env_wins"


# ===========================================================================
# Edge cases: SecretNotFoundError properties
# ===========================================================================


class TestSecretNotFoundError:
    """Verify SecretNotFoundError inherits proper structured fields."""

    def test_error_code(self) -> None:
        err = SecretNotFoundError("test")
        assert err.code == "secret_not_found"
        assert err.category == "secrets"

    def test_error_is_not_retryable(self) -> None:
        err = SecretNotFoundError("test")
        assert err.retryable is False
