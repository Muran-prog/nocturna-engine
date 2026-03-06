"""Comprehensive edge-case tests for BaseApiTool interface."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from aiohttp import web
from pydantic import ValidationError

from nocturna_engine.interfaces.base_api_tool import (
    ApiError,
    ApiEgressPolicyError,
    ApiOriginError,
    ApiTimeoutError,
    AuthenticationError,
    BaseApiTool,
    NetworkError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ServerError,
)
from nocturna_engine.interfaces.base_api_tool.models import ApiConfig, ApiResponse
from nocturna_engine.models.finding import Finding
from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.scan_result import ScanResult
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Concrete test subclass
# ---------------------------------------------------------------------------


class DummyApiTool(BaseApiTool):
    """Minimal concrete BaseApiTool subclass for tests."""

    name = "dummy_api"
    healthcheck_path = "/health"
    status_path_template = "/tasks/{task_id}"

    async def execute(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request_id=request.request_id, tool_name=self.name)

    async def parse_output(
        self,
        raw_output: dict[str, Any] | list[Any] | str | None,
        request: ScanRequest,
    ) -> list[Finding]:
        return []


def _cfg(base_url: str, **overrides: Any) -> ApiConfig:
    defaults = dict(
        base_url=base_url,
        api_key="test-key",
        verify_ssl=False,
        max_retries=3,
        rate_limit_per_second=50,
        pool_size=5,
    )
    defaults.update(overrides)
    return ApiConfig(**defaults)


# ---------------------------------------------------------------------------
# aiohttp test server fixture
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def api_server() -> Generator[dict[str, Any], None, None]:
    state: dict[str, int] = {"retry_429": 0, "retry_500": 0, "poll": 0}

    app = web.Application()

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"ok": True}, status=200)

    async def health_500(_: web.Request) -> web.Response:
        return web.json_response({"error": "down"}, status=500)

    async def json_ok(_: web.Request) -> web.Response:
        return web.json_response({"result": "ok"}, status=200)

    async def text_ok(_: web.Request) -> web.Response:
        return web.Response(text="plain-text-body", status=200, content_type="text/plain")

    async def empty_body(_: web.Request) -> web.Response:
        return web.Response(status=204)

    async def malformed_json(_: web.Request) -> web.Response:
        return web.Response(body=b"{not-json", status=200, content_type="application/json")

    async def json_list(_: web.Request) -> web.Response:
        return web.json_response([1, 2, 3], status=200)

    async def auth_401(_: web.Request) -> web.Response:
        return web.json_response({"error": "unauthorized"}, status=401)

    async def forbidden_403(_: web.Request) -> web.Response:
        return web.json_response({"error": "forbidden"}, status=403)

    async def not_found_404(_: web.Request) -> web.Response:
        return web.json_response({"error": "not found"}, status=404)

    async def rate_limit_429(_: web.Request) -> web.Response:
        state["retry_429"] += 1
        if state["retry_429"] == 1:
            return web.json_response(
                {"error": "too many"}, status=429, headers={"Retry-After": "0"},
            )
        return web.json_response({"ok": True}, status=200)

    async def server_error_500(_: web.Request) -> web.Response:
        state["retry_500"] += 1
        if state["retry_500"] < 3:
            return web.json_response({"error": "internal"}, status=500)
        return web.json_response({"ok": True}, status=200)

    async def server_502(_: web.Request) -> web.Response:
        return web.json_response({"error": "bad gateway"}, status=502)

    async def poll_task(_: web.Request) -> web.Response:
        state["poll"] += 1
        if state["poll"] < 3:
            return web.json_response({"status": "running"}, status=200)
        return web.json_response({"status": "succeeded"}, status=200)

    async def poll_fail(_: web.Request) -> web.Response:
        return web.json_response({"status": "failed"}, status=200)

    app.router.add_get("/health", health)
    app.router.add_get("/health_500", health_500)
    app.router.add_get("/json", json_ok)
    app.router.add_get("/text", text_ok)
    app.router.add_get("/empty", empty_body)
    app.router.add_get("/malformed_json", malformed_json)
    app.router.add_get("/json_list", json_list)
    app.router.add_get("/auth", auth_401)
    app.router.add_get("/forbidden", forbidden_403)
    app.router.add_get("/missing", not_found_404)
    app.router.add_get("/rate_limit", rate_limit_429)
    app.router.add_get("/retry_500", server_error_500)
    app.router.add_get("/bad_gateway", server_502)
    app.router.add_get("/tasks/{task_id}", poll_task)
    app.router.add_get("/tasks_fail/{task_id}", poll_fail)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    host, port = list(runner.addresses)[0]
    base_url = f"http://{host}:{port}"
    try:
        yield {"base_url": base_url, "state": state}
    finally:
        await site.stop()
        await runner.cleanup()


# ---------------------------------------------------------------------------
# 1. ApiConfig / ApiResponse model validation
# ---------------------------------------------------------------------------


class TestApiConfigModel:
    """Validate ApiConfig Pydantic model edge cases."""

    def test_minimal_valid_config(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com", api_key="key")
        assert cfg.base_url == "https://api.example.com"
        assert cfg.verify_ssl is True
        assert cfg.max_retries == 3
        assert cfg.rate_limit_per_second == 10

    def test_config_is_frozen(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com", api_key="key")
        with pytest.raises(ValidationError):
            cfg.base_url = "https://other.com"  # type: ignore[misc]

    def test_config_missing_base_url_raises(self) -> None:
        with pytest.raises(ValidationError):
            ApiConfig(api_key="key")  # type: ignore[call-arg]

    def test_config_missing_api_key_raises(self) -> None:
        with pytest.raises(ValidationError):
            ApiConfig(base_url="https://api.example.com")  # type: ignore[call-arg]

    def test_config_custom_timeouts(self) -> None:
        cfg = ApiConfig(
            base_url="https://x.com",
            api_key="k",
            timeout_total=120.0,
            timeout_connect=5.0,
            timeout_read=60.0,
        )
        assert cfg.timeout_total == 120.0
        assert cfg.timeout_connect == 5.0
        assert cfg.timeout_read == 60.0


class TestApiResponseModel:
    """Validate ApiResponse Pydantic model edge cases."""

    def test_minimal_response(self) -> None:
        resp = ApiResponse(status_code=200)
        assert resp.status_code == 200
        assert resp.body is None
        assert resp.headers == {}
        assert resp.duration_ms == 0.0

    def test_response_with_dict_body(self) -> None:
        resp = ApiResponse(status_code=200, body={"key": "val"})
        assert resp.body == {"key": "val"}

    def test_response_with_string_body(self) -> None:
        resp = ApiResponse(status_code=200, body="text")
        assert resp.body == "text"

    def test_response_is_frozen(self) -> None:
        resp = ApiResponse(status_code=200)
        with pytest.raises(ValidationError):
            resp.status_code = 404  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 2. Init with/without ApiConfig
# ---------------------------------------------------------------------------


class TestBaseApiToolInit:
    """Test BaseApiTool initialization edge cases."""

    def test_init_without_config(self) -> None:
        tool = DummyApiTool()
        assert tool.api_config is None
        assert tool._session is None

    def test_init_with_config(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        assert tool.api_config is cfg

    def test_rate_limit_defaults_to_1_without_config(self) -> None:
        tool = DummyApiTool()
        assert tool._rate_limit_per_second == 1

    def test_rate_limit_from_config(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="k", rate_limit_per_second=25)
        tool = DummyApiTool(api_config=cfg)
        assert tool._rate_limit_per_second == 25

    def test_set_api_config_updates_rate_limit(self) -> None:
        tool = DummyApiTool()
        assert tool._rate_limit_per_second == 1
        cfg = ApiConfig(base_url="https://x.com", api_key="k", rate_limit_per_second=42)
        tool._set_api_config(cfg)
        assert tool._rate_limit_per_second == 42
        assert tool.api_config is cfg

    def test_require_api_config_raises_without_config(self) -> None:
        tool = DummyApiTool()
        with pytest.raises(ApiError, match="not initialized"):
            tool._require_api_config()


# ---------------------------------------------------------------------------
# 3. Session lifecycle
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    """Test _init_client reuse, close, and context manager."""

    async def test_init_client_reuses_session(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        s1 = await tool._init_client()
        s2 = await tool._init_client()
        assert s1 is s2
        await tool.close()

    async def test_close_sets_session_to_none(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        session = await tool._init_client()
        assert not session.closed
        await tool.close()
        assert session.closed
        assert tool._session is None

    async def test_close_idempotent(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        await tool._init_client()
        await tool.close()
        await tool.close()  # should not raise
        assert tool._session is None

    async def test_close_without_init(self) -> None:
        tool = DummyApiTool()
        await tool.close()  # no-op, should not raise

    async def test_aenter_creates_session_with_config(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        result = await tool.__aenter__()
        assert result is tool
        assert tool._session is not None
        await tool.__aexit__(None, None, None)
        assert tool._session is None

    async def test_aenter_without_config_no_session(self) -> None:
        tool = DummyApiTool()
        result = await tool.__aenter__()
        assert result is tool
        assert tool._session is None
        await tool.__aexit__(None, None, None)

    async def test_setup_inits_session_with_config(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        await tool.setup()
        assert tool._session is not None
        assert tool._is_initialized is True
        await tool.teardown()
        assert tool._session is None
        assert tool._is_initialized is False

    async def test_init_client_raises_without_config(self) -> None:
        tool = DummyApiTool()
        with pytest.raises(ApiError):
            await tool._init_client()


# ---------------------------------------------------------------------------
# 4. Health check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    """Test health_check success, failure, and no-config cases."""

    async def test_health_check_success(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        assert await tool.health_check() is True
        await tool.close()

    async def test_health_check_returns_false_on_500(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        tool.healthcheck_path = "/health_500"
        assert await tool.health_check() is False
        await tool.close()

    async def test_health_check_returns_false_without_config(self) -> None:
        tool = DummyApiTool()
        assert await tool.health_check() is False


# ---------------------------------------------------------------------------
# 5. Response decoding
# ---------------------------------------------------------------------------


class TestResponseDecoding:
    """Test _decode_response_body for JSON, text, None, malformed."""

    async def test_json_response_decoded(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", "/json", retry=False)
        assert resp.body == {"result": "ok"}
        await tool.close()

    async def test_text_response_decoded(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", "/text", retry=False)
        assert resp.body == "plain-text-body"
        await tool.close()

    async def test_empty_body_returns_none(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", "/empty", retry=False)
        assert resp.body is None
        await tool.close()

    async def test_malformed_json_falls_back_to_text(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", "/malformed_json", retry=False)
        # malformed JSON should fall back to text
        assert isinstance(resp.body, str)
        await tool.close()

    async def test_json_list_wrapped_in_dict(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", "/json_list", retry=False)
        # non-dict JSON gets wrapped as {"value": [1,2,3]}
        assert resp.body == {"value": [1, 2, 3]}
        await tool.close()


# ---------------------------------------------------------------------------
# 6. HTTP error mapping (parametrized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "error_type"),
    [
        ("/auth", AuthenticationError),
        ("/forbidden", PermissionError),
        ("/missing", NotFoundError),
        ("/bad_gateway", ServerError),
    ],
)
async def test_status_code_maps_to_typed_error(
    api_server: dict[str, Any],
    path: str,
    error_type: type[Exception],
) -> None:
    """HTTP 401/403/404/5xx should map to typed exceptions."""
    tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
    with pytest.raises(error_type):
        await tool._request("GET", path, retry=False)
    await tool.close()


class TestErrorMappingInternal:
    """Test _map_http_error directly for comprehensive coverage."""

    def test_401_maps_to_authentication_error(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(status_code=401, path="/x", body=None, retry_after=None)
        assert isinstance(err, AuthenticationError)

    def test_403_maps_to_permission_error(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(status_code=403, path="/x", body=None, retry_after=None)
        assert isinstance(err, PermissionError)

    def test_404_maps_to_not_found_error(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(status_code=404, path="/x", body=None, retry_after=None)
        assert isinstance(err, NotFoundError)

    def test_429_maps_to_rate_limit_error(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(status_code=429, path="/x", body=None, retry_after=5.0)
        assert isinstance(err, RateLimitError)
        assert err.retry_after_seconds == 5.0

    def test_500_maps_to_server_error(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(status_code=500, path="/x", body=None, retry_after=None)
        assert isinstance(err, ServerError)

    def test_503_maps_to_server_error(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(status_code=503, path="/x", body=None, retry_after=None)
        assert isinstance(err, ServerError)

    def test_418_maps_to_generic_api_error(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(status_code=418, path="/x", body=None, retry_after=None)
        assert type(err) is ApiError

    def test_error_message_includes_body_text(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(
            status_code=401, path="/x", body={"error": "bad key"}, retry_after=None
        )
        assert "bad key" in str(err)

    def test_error_body_string_included(self) -> None:
        tool = DummyApiTool()
        err = tool._map_http_error(
            status_code=500, path="/x", body="raw error text", retry_after=None
        )
        assert "raw error text" in str(err)


# ---------------------------------------------------------------------------
# 7. Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Test _enforce_rate_limit throttling behavior."""

    async def test_rate_limit_allows_burst_up_to_limit(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="k", rate_limit_per_second=5)
        tool = DummyApiTool(api_config=cfg)
        # Should be able to enforce rate_limit 5 times without blocking
        for _ in range(5):
            await tool._enforce_rate_limit()

    async def test_rate_limit_zero_or_negative_skips(self) -> None:
        tool = DummyApiTool()
        tool._rate_limit_per_second = 0
        await tool._enforce_rate_limit()  # should not block or raise


# ---------------------------------------------------------------------------
# 8. Request retries (429, 5xx, transport)
# ---------------------------------------------------------------------------


class TestRetries:
    """Test retry behavior for various failure modes."""

    async def test_429_retried_and_recovers(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", "/rate_limit", retry=True)
        assert resp.status_code == 200
        assert api_server["state"]["retry_429"] == 2
        await tool.close()

    async def test_429_without_retry_raises(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        with pytest.raises(RateLimitError):
            await tool._request("GET", "/rate_limit", retry=False)
        await tool.close()

    async def test_5xx_retried_and_recovers(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", "/retry_500", retry=True)
        assert resp.status_code == 200
        assert api_server["state"]["retry_500"] == 3
        await tool.close()

    async def test_5xx_without_retry_raises(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        with pytest.raises(ServerError):
            await tool._request("GET", "/bad_gateway", retry=False)
        await tool.close()

    async def test_empty_method_raises(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        with pytest.raises(ApiError, match="non-empty"):
            await tool._request("", "/json", retry=False)
        await tool.close()


# ---------------------------------------------------------------------------
# 9. Path normalization and cross-origin rejection
# ---------------------------------------------------------------------------


class TestPathNormalization:
    """Test _normalize_path and cross-origin blocking."""

    def test_empty_path_returns_root(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        assert tool._normalize_path("") == "/"

    def test_none_like_path_returns_root(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        assert tool._normalize_path("  ") == "/"

    def test_relative_path_gets_slash_prefix(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        assert tool._normalize_path("v1/scan") == "/v1/scan"

    def test_absolute_path_unchanged(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        assert tool._normalize_path("/v1/scan") == "/v1/scan"

    async def test_same_origin_absolute_url_normalized(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        resp = await tool._request("GET", f"{api_server['base_url']}/json", retry=False)
        assert resp.status_code == 200
        await tool.close()

    async def test_cross_origin_absolute_url_rejected(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        with pytest.raises(ApiOriginError, match="Cross-origin"):
            await tool._request("GET", "https://evil.com/steal", retry=False)
        await tool.close()

    def test_cross_origin_different_port_rejected(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com:443", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        with pytest.raises(ApiOriginError):
            tool._normalize_path("https://api.example.com:8443/path")

    def test_cross_origin_different_scheme_rejected(self) -> None:
        cfg = ApiConfig(base_url="https://api.example.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        with pytest.raises(ApiOriginError):
            tool._normalize_path("http://api.example.com/path")


# ---------------------------------------------------------------------------
# 10. Egress policy enforcement
# ---------------------------------------------------------------------------


class TestEgressPolicy:
    """Test egress policy enforcement via runtime context."""

    async def test_egress_deny_host_blocks_request(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        tool.bind_runtime_context(
            SimpleNamespace(policy={
                "egress_deny_hosts": ["127.0.0.1"],
                "default_egress_action": "allow",
            })
        )
        with pytest.raises(ApiEgressPolicyError) as exc_info:
            await tool._request("GET", "/json", retry=False)
        assert exc_info.value.code == "policy_denied_egress_host"
        await tool.close()

    async def test_no_runtime_context_allows_request(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        # No runtime context bound - should pass
        resp = await tool._request("GET", "/json", retry=False)
        assert resp.status_code == 200
        await tool.close()

    async def test_empty_policy_allows_request(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        tool.bind_runtime_context(SimpleNamespace(policy={}))
        resp = await tool._request("GET", "/json", retry=False)
        assert resp.status_code == 200
        await tool.close()

    async def test_non_mapping_policy_allows_request(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        tool.bind_runtime_context(SimpleNamespace(policy="not a dict"))
        resp = await tool._request("GET", "/json", retry=False)
        assert resp.status_code == 200
        await tool.close()


# ---------------------------------------------------------------------------
# 10b. Engine-level SSL enforcement
# ---------------------------------------------------------------------------


class TestSslEnforcement:
    """Test engine-level SSL enforcement in _init_client."""

    async def test_ssl_disabled_with_require_ssl_policy_raises(self) -> None:
        """verify_ssl=False + engine require_ssl=True should raise ApiError."""
        cfg = ApiConfig(base_url="https://api.example.com", api_key="k", verify_ssl=False)
        tool = DummyApiTool(api_config=cfg)
        tool.bind_runtime_context(SimpleNamespace(
            config={"security": {"require_ssl": True}},
            policy={},
        ))
        with pytest.raises(ApiError, match="SSL verification is required"):
            await tool._init_client()

    async def test_ssl_disabled_without_require_ssl_policy_warns(self, api_server: dict[str, Any]) -> None:
        """verify_ssl=False + require_ssl=False should succeed (just warning)."""
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"], verify_ssl=False))
        tool.bind_runtime_context(SimpleNamespace(
            config={"security": {"require_ssl": False}},
            policy={},
        ))
        session = await tool._init_client()
        assert session is not None
        await tool.close()

    async def test_ssl_enabled_with_require_ssl_policy_passes(self, api_server: dict[str, Any]) -> None:
        """verify_ssl=True + require_ssl=True should work fine."""
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"], verify_ssl=True))
        tool.bind_runtime_context(SimpleNamespace(
            config={"security": {"require_ssl": True}},
            policy={},
        ))
        session = await tool._init_client()
        assert session is not None
        await tool.close()

    async def test_ssl_disabled_without_runtime_context_warns(self, api_server: dict[str, Any]) -> None:
        """verify_ssl=False + no runtime context should fall through (warning only)."""
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"], verify_ssl=False))
        session = await tool._init_client()
        assert session is not None
        await tool.close()

    async def test_ssl_disabled_with_non_dict_config_allows(self, api_server: dict[str, Any]) -> None:
        """verify_ssl=False + runtime context with non-dict config should fall through."""
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"], verify_ssl=False))
        tool.bind_runtime_context(SimpleNamespace(config="not a dict", policy={}))
        session = await tool._init_client()
        assert session is not None
        await tool.close()

    async def test_ssl_disabled_with_missing_security_key_allows(self, api_server: dict[str, Any]) -> None:
        """verify_ssl=False + runtime context with no security key should fall through."""
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"], verify_ssl=False))
        tool.bind_runtime_context(SimpleNamespace(config={"other": True}, policy={}))
        session = await tool._init_client()
        assert session is not None
        await tool.close()

# ---------------------------------------------------------------------------
# 11. Polling
# ---------------------------------------------------------------------------


class TestPolling:
    """Test _poll_status edge cases."""

    async def test_poll_until_terminal(self, api_server: dict[str, Any]) -> None:
        tool = DummyApiTool(api_config=_cfg(api_server["base_url"]))
        payload = await tool._poll_status("t1", interval=0.01, max_wait=2.0)
        assert payload["status"] == "succeeded"
        await tool.close()

    async def test_poll_empty_task_id_raises(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        with pytest.raises(ApiError, match="non-empty"):
            await tool._poll_status("  ", interval=1.0, max_wait=1.0)

    async def test_poll_zero_interval_raises(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        with pytest.raises(ApiError, match="greater than zero"):
            await tool._poll_status("t1", interval=0, max_wait=1.0)

    async def test_poll_zero_max_wait_raises(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="k")
        tool = DummyApiTool(api_config=cfg)
        with pytest.raises(ApiError, match="greater than zero"):
            await tool._poll_status("t1", interval=1.0, max_wait=0)


# ---------------------------------------------------------------------------
# 12. Retry-After header parsing
# ---------------------------------------------------------------------------


class TestRetryAfterParsing:
    """Test _extract_retry_after_seconds edge cases."""

    def test_valid_numeric(self) -> None:
        assert DummyApiTool._extract_retry_after_seconds({"Retry-After": "5"}) == 5.0

    def test_float_value(self) -> None:
        assert DummyApiTool._extract_retry_after_seconds({"Retry-After": "1.5"}) == 1.5

    def test_negative_clamped_to_zero(self) -> None:
        assert DummyApiTool._extract_retry_after_seconds({"Retry-After": "-3"}) == 0.0

    def test_missing_header_returns_none(self) -> None:
        assert DummyApiTool._extract_retry_after_seconds({}) is None

    def test_empty_string_returns_none(self) -> None:
        assert DummyApiTool._extract_retry_after_seconds({"Retry-After": ""}) is None

    def test_non_numeric_returns_none(self) -> None:
        assert DummyApiTool._extract_retry_after_seconds({"Retry-After": "abc"}) is None


# ---------------------------------------------------------------------------
# 13. Backoff computation
# ---------------------------------------------------------------------------


class TestBackoff:
    """Test _compute_backoff_seconds."""

    def test_attempt_zero(self) -> None:
        delay = DummyApiTool._compute_backoff_seconds(0)
        assert 0.5 <= delay <= 0.7  # 0.5 base + up to 0.1 jitter

    def test_attempt_one(self) -> None:
        delay = DummyApiTool._compute_backoff_seconds(1)
        assert 1.0 <= delay <= 1.2

    def test_attempt_capped_at_8(self) -> None:
        delay = DummyApiTool._compute_backoff_seconds(100)
        assert delay <= 8.2  # 8.0 cap + 0.1 jitter max


# ---------------------------------------------------------------------------
# 14. Build default headers
# ---------------------------------------------------------------------------


class TestBuildHeaders:
    """Test _build_default_headers."""

    def test_headers_include_auth(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="my-secret-key")
        headers = DummyApiTool._build_default_headers(cfg)
        assert headers["Authorization"] == "Bearer my-secret-key"
        assert "X-API-Key" not in headers
        assert headers["Accept"] == "application/json"
        assert "NocturnaEngine" in headers["User-Agent"]

    def test_headers_x_api_key_mode(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="my-secret-key", auth_header_mode="x-api-key")
        headers = DummyApiTool._build_default_headers(cfg)
        assert headers["X-API-Key"] == "my-secret-key"
        assert "Authorization" not in headers

    def test_headers_both_mode(self) -> None:
        cfg = ApiConfig(base_url="https://x.com", api_key="my-secret-key", auth_header_mode="both")
        headers = DummyApiTool._build_default_headers(cfg)
        assert headers["Authorization"] == "Bearer my-secret-key"
        assert headers["X-API-Key"] == "my-secret-key"


# ---------------------------------------------------------------------------
# 15. Build request kwargs
# ---------------------------------------------------------------------------


class TestBuildRequestKwargs:
    """Test _build_request_kwargs."""

    def test_none_data_no_params(self) -> None:
        result = DummyApiTool._build_request_kwargs(data=None, params=None)
        assert result == {}

    def test_dict_data_uses_json(self) -> None:
        result = DummyApiTool._build_request_kwargs(data={"a": 1}, params=None)
        assert result == {"json": {"a": 1}}

    def test_list_data_uses_json(self) -> None:
        result = DummyApiTool._build_request_kwargs(data=[1, 2], params=None)
        assert result == {"json": [1, 2]}

    def test_string_data_uses_data(self) -> None:
        result = DummyApiTool._build_request_kwargs(data="raw", params=None)
        assert result == {"data": "raw"}

    def test_params_included(self) -> None:
        result = DummyApiTool._build_request_kwargs(data=None, params={"q": "x"})
        assert result == {"params": {"q": "x"}}


# ---------------------------------------------------------------------------
# 16. Extract body message
# ---------------------------------------------------------------------------


class TestExtractBodyMessage:
    """Test _extract_body_message edge cases."""

    def test_none_body(self) -> None:
        assert DummyApiTool._extract_body_message(None) == ""

    def test_dict_error_key(self) -> None:
        assert DummyApiTool._extract_body_message({"error": "oops"}) == "oops"

    def test_dict_message_key(self) -> None:
        assert DummyApiTool._extract_body_message({"message": "msg"}) == "msg"

    def test_dict_detail_key(self) -> None:
        assert DummyApiTool._extract_body_message({"detail": "det"}) == "det"

    def test_dict_no_matching_key_returns_str(self) -> None:
        result = DummyApiTool._extract_body_message({"other": 123})
        assert len(result) > 0  # str representation of dict

    def test_string_body(self) -> None:
        assert DummyApiTool._extract_body_message("some text") == "some text"

    def test_long_body_truncated(self) -> None:
        result = DummyApiTool._extract_body_message("x" * 600)
        assert len(result) <= 500


# ---------------------------------------------------------------------------
# 17. Origin signature / sanitize path
# ---------------------------------------------------------------------------


class TestOriginHelpers:
    """Test _origin_signature and _sanitize_path_for_log."""

    def test_origin_signature_defaults_http_port(self) -> None:
        from urllib.parse import urlsplit
        parsed = urlsplit("http://example.com/path")
        scheme, host, port = DummyApiTool._origin_signature(parsed)
        assert (scheme, host, port) == ("http", "example.com", 80)

    def test_origin_signature_defaults_https_port(self) -> None:
        from urllib.parse import urlsplit
        parsed = urlsplit("https://example.com/path")
        scheme, host, port = DummyApiTool._origin_signature(parsed)
        assert (scheme, host, port) == ("https", "example.com", 443)

    def test_origin_signature_custom_port(self) -> None:
        from urllib.parse import urlsplit
        parsed = urlsplit("https://example.com:8443/path")
        scheme, host, port = DummyApiTool._origin_signature(parsed)
        assert port == 8443

    def test_sanitize_path_strips_query(self) -> None:
        result = DummyApiTool._sanitize_path_for_log("/path?secret=token")
        assert "secret" not in result
        assert result == "/path"

    def test_sanitize_empty_path(self) -> None:
        result = DummyApiTool._sanitize_path_for_log("")
        assert result == "/"

    def test_origin_for_log_unknown_when_empty(self) -> None:
        from urllib.parse import urlsplit
        parsed = urlsplit("")
        label = DummyApiTool._origin_for_log(parsed)
        assert label == "unknown"