"""Core BaseApiTool definition and session lifecycle."""

from __future__ import annotations

import asyncio
from abc import ABC
from collections import deque
from typing import Any

import aiohttp
from structlog.stdlib import BoundLogger

from nocturna_engine.interfaces.base_tool import BaseTool
from nocturna_engine.interfaces.base_api_tool.models import ApiConfig

from ..errors import ApiError, AuthenticationError, PermissionError
from .polling import ApiPollingMixin
from .policy import ApiPathPolicyMixin
from .request import ApiRequestMixin


class BaseApiTool(ApiRequestMixin, ApiPollingMixin, ApiPathPolicyMixin, BaseTool, ABC):
    """Intermediate base class for API-backed plugins.

    This class centralizes:
    - ClientSession lifecycle and connection pooling.
    - Request retry logic with exponential backoff.
    - Per-second request throttling and concurrency gating.
    - Status polling for async API jobs.
    """

    healthcheck_path: str = "/"
    status_path_template: str = "/v0.1/scan/{task_id}"
    terminal_poll_statuses: frozenset[str] = frozenset({"succeeded", "failed", "paused", "cancelled"})

    def __init__(
        self,
        *,
        api_config: ApiConfig | None = None,
        logger: BoundLogger | None = None,
    ) -> None:
        """Initialize base API tool state.

        Args:
            api_config: Optional API configuration. Plugins may set it lazily.
            logger: Optional structured logger instance.
        """

        super().__init__(logger=logger)
        self._api_config: ApiConfig | None = api_config
        self._session: aiohttp.ClientSession | None = None
        rate = max(1, int(api_config.rate_limit_per_second)) if api_config is not None else 1
        self._rate_limit_per_second = rate
        self._rate_limit_semaphore = asyncio.Semaphore(rate)
        self._rate_lock = asyncio.Lock()
        self._rate_timestamps: deque[float] = deque()
        self._runtime_context: Any | None = None

    @property
    def api_config(self) -> ApiConfig | None:
        """Return current API configuration, if set."""

        return self._api_config

    def _set_api_config(self, api_config: ApiConfig) -> None:
        """Update API configuration and reset request throttling state.

        Args:
            api_config: Validated API configuration model.
        """

        self._api_config = api_config
        rate = max(1, int(api_config.rate_limit_per_second))
        self._rate_limit_per_second = rate
        self._rate_limit_semaphore = asyncio.Semaphore(rate)
        self._rate_timestamps.clear()

    def bind_runtime_context(self, context: Any) -> None:
        """Attach runtime context injected by v2 adapter flow."""

        self._runtime_context = context

    async def setup(self) -> None:
        """Initialize API session when configuration is available."""

        if self._api_config is not None:
            await self._init_client()
        await super().setup()

    async def teardown(self) -> None:
        """Close API session on tool teardown."""

        await self.close()
        await super().teardown()

    async def __aenter__(self) -> "BaseApiTool":
        """Enter async context and ensure session exists when configured."""

        if self._api_config is not None:
            await self._init_client()
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: Any) -> None:
        """Exit async context and close session.

        Args:
            exc_type: Optional exception type.
            exc: Optional exception instance.
            tb: Optional traceback.
        """

        _ = exc_type
        _ = exc
        _ = tb
        await self.close()

    async def _init_client(self) -> aiohttp.ClientSession:
        """Create or reuse shared aiohttp client session.

        Returns:
            aiohttp.ClientSession: Reusable configured session.

        Raises:
            ApiError: If API config is missing.
        """

        config = self._require_api_config()

        # Engine-level SSL enforcement: deny verify_ssl=False when policy requires SSL.
        if not config.verify_ssl and self._runtime_context is not None:
            engine_config = getattr(self._runtime_context, "config", None)
            if isinstance(engine_config, dict):
                security = engine_config.get("security")
                if isinstance(security, dict) and security.get("require_ssl") is True:
                    raise ApiError(
                        "SSL verification is required by engine security policy. "
                        "Set engine.security.require_ssl=false to override."
                    )

        if self._session is not None and not self._session.closed:
            return self._session

        timeout = aiohttp.ClientTimeout(
            total=float(config.timeout_total),
            connect=float(config.timeout_connect),
            sock_read=float(config.timeout_read),
        )
        connector = aiohttp.TCPConnector(
            limit=int(config.pool_size),
            limit_per_host=int(config.pool_size),
            ssl=config.verify_ssl,
        )
        default_headers = self._build_default_headers(config)
        self._session = aiohttp.ClientSession(
            base_url=config.base_url.rstrip("/"),
            timeout=timeout,
            headers=default_headers,
            connector=connector,
            raise_for_status=False,
        )

        if not config.verify_ssl:
            self.logger.warning(
                "api_ssl_verification_disabled",
                base_url=config.base_url,
            )
        return self._session

    async def health_check(self) -> bool:
        """Check whether the API endpoint is reachable and responsive.

        Returns:
            bool: True when health endpoint responds successfully.

        Raises:
            AuthenticationError: If API key is invalid.
            PermissionError: If API key lacks permissions.
        """

        if self._api_config is None:
            return False
        try:
            response = await self._request("GET", self.healthcheck_path, retry=False)
        except (AuthenticationError, PermissionError):
            raise
        except ApiError:
            return False
        return 200 <= response.status_code < 400

    async def close(self) -> None:
        """Close shared aiohttp session."""

        if self._session is None:
            return
        if not self._session.closed:
            await self._session.close()
        self._session = None

    def _require_api_config(self) -> ApiConfig:
        """Return API config or raise if not configured.

        Returns:
            ApiConfig: Active API config.

        Raises:
            ApiError: If API config has not been provided.
        """

        if self._api_config is None:
            raise ApiError("API configuration is not initialized for this tool.")
        return self._api_config

    @staticmethod
    def _build_default_headers(config: ApiConfig) -> dict[str, str]:
        """Build safe default headers for API requests.

        Args:
            config: API configuration model.

        Returns:
            dict[str, str]: Default request headers.
        """

        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "NocturnaEngine-ApiTool/1.0",
        }
        if config.auth_header_mode in ("bearer", "both"):
            headers["Authorization"] = f"Bearer {config.api_key}"
        if config.auth_header_mode in ("x-api-key", "both"):
            headers["X-API-Key"] = config.api_key
        return headers
