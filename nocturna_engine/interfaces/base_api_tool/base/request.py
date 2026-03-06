"""HTTP request execution and response handling for BaseApiTool."""

from __future__ import annotations

import asyncio
import random
from collections import deque
from time import monotonic, perf_counter
from typing import Any

import aiohttp

from nocturna_engine.interfaces.base_api_tool.models import ApiResponse

from ..errors import (
    ApiError,
    AuthenticationError,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
)


class ApiRequestMixin:
    """Mixin with request lifecycle, retries, and throttling."""

    async def _request(
        self,
        method: str,
        path: str,
        data: Any = None,
        params: dict[str, Any] | None = None,
        retry: bool = True,
    ) -> ApiResponse:
        """Perform an HTTP request with retries, throttling, and typed response.

        Args:
            method: HTTP method.
            path: Relative API path.
            data: Optional request payload.
            params: Optional query parameters.
            retry: Whether retries are enabled.

        Returns:
            ApiResponse: Normalized response payload.

        Raises:
            AuthenticationError: On HTTP 401.
            PermissionError: On HTTP 403.
            NotFoundError: On HTTP 404.
            RateLimitError: On HTTP 429 without successful retry.
            ServerError: On HTTP 5xx without successful retry.
            NetworkError: On persistent transport failures.
            ApiError: On other request failures.
        """

        config = self._require_api_config()
        session = await self._init_client()
        normalized_method = str(method or "").strip().upper()
        if not normalized_method:
            raise ApiError("HTTP method must be non-empty.")

        request_path = self._normalize_path(path)
        log_path = self._sanitize_path_for_log(request_path)
        self._enforce_egress_policy(request_path=request_path)
        max_attempts = 1 + (int(config.max_retries) if retry else 0)

        for attempt in range(max_attempts):
            started = perf_counter()
            await self._enforce_rate_limit()
            request_kwargs = self._build_request_kwargs(data=data, params=params)
            try:
                async with self._rate_limit_semaphore:
                    async with session.request(
                        method=normalized_method,
                        url=request_path,
                        **request_kwargs,
                    ) as response:
                        body = await self._decode_response_body(response)
                        duration_ms = (perf_counter() - started) * 1000.0
                        api_response = ApiResponse(
                            status_code=int(response.status),
                            headers={str(key): str(value) for key, value in response.headers.items()},
                            body=body,
                            duration_ms=round(duration_ms, 3),
                            request_method=normalized_method,
                            request_path=request_path,
                        )
                self.logger.info(
                    "api_request_completed",
                    method=normalized_method,
                    path=log_path,
                    status=api_response.status_code,
                    duration_ms=api_response.duration_ms,
                )

                if 200 <= api_response.status_code < 300:
                    return api_response

                retry_after = self._extract_retry_after_seconds(api_response.headers)
                error = self._map_http_error(
                    status_code=api_response.status_code,
                    path=log_path,
                    body=api_response.body,
                    retry_after=retry_after,
                )
                should_retry = retry and attempt < (max_attempts - 1)
                if should_retry and api_response.status_code == 429:
                    await asyncio.sleep(max(retry_after or 0.0, self._compute_backoff_seconds(attempt)))
                    continue
                if should_retry and 500 <= api_response.status_code < 600:
                    await asyncio.sleep(self._compute_backoff_seconds(attempt))
                    continue
                raise error
            except (
                aiohttp.ClientConnectionError,
                aiohttp.ServerDisconnectedError,
                aiohttp.ClientPayloadError,
                aiohttp.ClientOSError,
                asyncio.TimeoutError,
            ) as exc:
                duration_ms = (perf_counter() - started) * 1000.0
                self.logger.warning(
                    "api_request_transport_error",
                    method=normalized_method,
                    path=log_path,
                    duration_ms=round(duration_ms, 3),
                    error=str(exc),
                )
                should_retry = retry and attempt < (max_attempts - 1)
                if should_retry:
                    await asyncio.sleep(self._compute_backoff_seconds(attempt))
                    continue
                raise NetworkError(
                    f"API transport error for {normalized_method} {log_path}: {exc}"
                ) from exc

        raise ApiError(f"API request failed after retries: {normalized_method} {log_path}")

    @staticmethod
    def _build_request_kwargs(
        *,
        data: Any,
        params: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Prepare request kwargs while preserving JSON behavior."""

        kwargs: dict[str, Any] = {}
        if params is not None:
            kwargs["params"] = params
        if data is None:
            return kwargs
        if isinstance(data, (dict, list)):
            kwargs["json"] = data
            return kwargs
        kwargs["data"] = data
        return kwargs

    async def _decode_response_body(self, response: aiohttp.ClientResponse) -> dict[str, Any] | str | None:
        """Decode API response body based on content type.

        Args:
            response: aiohttp response object.

        Returns:
            dict[str, Any] | str | None: Parsed JSON dict, text, or None.
        """

        content_type = response.headers.get("Content-Type", "").lower()
        if "json" in content_type:
            try:
                parsed = await response.json(content_type=None)
            except Exception:
                text_fallback = await response.text()
                return text_fallback or None
            if isinstance(parsed, dict):
                return parsed
            if parsed is None:
                return None
            return {"value": parsed}
        text = await response.text()
        return text or None

    @staticmethod
    def _extract_retry_after_seconds(headers: dict[str, str]) -> float | None:
        """Parse retry-after header value as seconds."""

        value = headers.get("Retry-After")
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            seconds = float(text)
        except ValueError:
            return None
        return max(0.0, seconds)

    @staticmethod
    def _compute_backoff_seconds(attempt: int) -> float:
        """Compute exponential backoff delay with jitter."""

        base_delay = min(8.0, 0.5 * (2 ** max(attempt, 0)))
        jitter = random.uniform(0.0, 0.1)
        return base_delay + jitter

    def _map_http_error(
        self,
        *,
        status_code: int,
        path: str,
        body: dict[str, Any] | str | None,
        retry_after: float | None,
    ) -> ApiError:
        """Map HTTP status code to typed API exception."""

        body_text = self._extract_body_message(body)
        prefix = f"API {status_code} on {path}"
        if body_text:
            prefix = f"{prefix}: {body_text}"
        if status_code == 401:
            return AuthenticationError(prefix)
        if status_code == 403:
            return PermissionError(prefix)
        if status_code == 404:
            return NotFoundError(prefix)
        if status_code == 429:
            return RateLimitError(prefix, retry_after_seconds=retry_after)
        if 500 <= status_code < 600:
            return ServerError(prefix)
        return ApiError(prefix)

    @staticmethod
    def _extract_body_message(body: dict[str, Any] | str | None) -> str:
        """Extract compact message text from API response body."""

        if body is None:
            return ""
        if isinstance(body, dict):
            for key in ("error", "message", "detail", "title"):
                value = body.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            rendered = str(body).strip()
            return rendered[:500]
        rendered = str(body).strip()
        return rendered[:500]

    async def _enforce_rate_limit(self) -> None:
        """Throttle requests to configured requests-per-second budget."""

        if self._rate_limit_per_second <= 0:
            return
        while True:
            async with self._rate_lock:
                now = monotonic()
                while self._rate_timestamps and (now - self._rate_timestamps[0]) >= 1.0:
                    self._rate_timestamps.popleft()
                if len(self._rate_timestamps) < self._rate_limit_per_second:
                    self._rate_timestamps.append(now)
                    return
                sleep_for = max(0.0, 1.0 - (now - self._rate_timestamps[0]))
            if sleep_for <= 0:
                await asyncio.sleep(0)
            else:
                await asyncio.sleep(sleep_for)
