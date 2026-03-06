"""Secret retrieval service using env vars and optional keyring."""

from __future__ import annotations

import os
from typing import Final

from nocturna_engine.exceptions import SecretNotFoundError


class SecretService:
    """Provide secure secret lookup without hardcoding credentials."""

    def __init__(self, env_prefix: str = "NOCTURNA_SECRET", keyring_service: str = "nocturna_engine") -> None:
        """Initialize service.

        Args:
            env_prefix: Environment variable prefix for secrets.
            keyring_service: Service namespace for keyring lookup.
        """

        self._env_prefix: Final[str] = env_prefix
        self._keyring_service: Final[str] = keyring_service

    def get_secret(self, name: str, required: bool = True) -> str | None:
        """Fetch secret from env vars first, then keyring.

        Args:
            name: Secret logical name.
            required: Whether absence should raise an exception.

        Returns:
            str | None: Secret value when available.

        Raises:
            SecretNotFoundError: If secret is required but missing.
        """

        normalized = name.strip().upper().replace("-", "_")
        candidates = [f"{self._env_prefix}_{normalized}", normalized]
        for env_name in candidates:
            value = os.getenv(env_name)
            if value:
                return value

        value = self._get_from_keyring(name)
        if value:
            return value

        if required:
            raise SecretNotFoundError(f"Required secret not found: {name}")
        return None

    def _get_from_keyring(self, name: str) -> str | None:
        """Fetch secret from keyring if dependency is available.

        Args:
            name: Secret logical name.

        Returns:
            str | None: Secret value or None.
        """

        try:
            import keyring  # type: ignore
        except ImportError:
            return None
        return keyring.get_password(self._keyring_service, name)

