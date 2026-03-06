"""Comprehensive edge-case tests for LoggingService and masking utilities."""

from __future__ import annotations

from typing import Any

import pytest

from nocturna_engine.services.logging_service import (
    LoggingService,
    _mask_ipv4,
    _mask_ipv6,
    _mask_jwt,
    _mask_token_like,
    _mask_url_params,
    _mask_value,
    redact_sensitive_processor,
)


# ===========================================================================
# _mask_ipv4 edge cases
# ===========================================================================


class TestMaskIpv4:
    """Tests for IPv4 address masking."""

    def test_standard_ip(self) -> None:
        assert _mask_ipv4("192.168.1.100") == "192.168.x.x"

    def test_zero_ip(self) -> None:
        assert _mask_ipv4("0.0.0.0") == "0.0.x.x"

    def test_max_ip(self) -> None:
        assert _mask_ipv4("255.255.255.255") == "255.255.x.x"

    def test_ip_embedded_in_text(self) -> None:
        result = _mask_ipv4("Connection from 10.0.0.1 was refused")
        assert result == "Connection from 10.0.x.x was refused"

    def test_multiple_ips(self) -> None:
        result = _mask_ipv4("src=1.2.3.4 dst=5.6.7.8")
        assert result == "src=1.2.x.x dst=5.6.x.x"

    def test_no_ips(self) -> None:
        text = "no addresses here"
        assert _mask_ipv4(text) == text

    def test_partial_ip_not_masked(self) -> None:
        """Sequences that look like partial IPs should not match full pattern."""
        text = "version 1.2.3"
        # Only 3 octets — not a valid IPv4 quad; should stay unchanged
        assert _mask_ipv4(text) == text

    def test_ip_at_string_boundaries(self) -> None:
        assert _mask_ipv4("10.20.30.40") == "10.20.x.x"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("127.0.0.1", "127.0.x.x"),
            ("192.168.0.1", "192.168.x.x"),
            ("172.16.0.1", "172.16.x.x"),
        ],
    )
    def test_common_private_ips(self, raw: str, expected: str) -> None:
        assert _mask_ipv4(raw) == expected

    def test_cidr_suffix_preserved(self) -> None:
        assert _mask_ipv4("10.0.0.0/8") == "10.0.x.x/8"

    def test_cidr_32(self) -> None:
        assert _mask_ipv4("192.168.1.1/32") == "192.168.x.x/32"

    def test_cidr_in_text(self) -> None:
        result = _mask_ipv4("subnet 10.0.0.0/24 is allowed")
        assert result == "subnet 10.0.x.x/24 is allowed"


# ===========================================================================
# _mask_ipv6 edge cases
# ===========================================================================


class TestMaskIpv6:
    """Tests for IPv6 address masking."""

    def test_full_ipv6(self) -> None:
        result = _mask_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result == "2001:0db8:x:x:x:x:x:x"

    def test_short_ipv6(self) -> None:
        result = _mask_ipv6("fe80:1:2:3:4:5:6:7")
        assert result == "fe80:1:x:x:x:x:x:x"

    def test_ipv6_in_text(self) -> None:
        result = _mask_ipv6("connection from 2001:db8:1:2:3:4:5:6 established")
        assert result == "connection from 2001:db8:x:x:x:x:x:x established"

    def test_three_group_ipv6(self) -> None:
        result = _mask_ipv6("fe80:1:abcd")
        assert result == "fe80:1:x"

    def test_no_ipv6(self) -> None:
        text = "no ipv6 here"
        assert _mask_ipv6(text) == text


# ===========================================================================
# _mask_jwt edge cases
# ===========================================================================


class TestMaskJwt:
    """Tests for JWT masking."""

    def test_standard_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert _mask_jwt(jwt) == "***JWT_REDACTED***"

    def test_jwt_in_text(self) -> None:
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = _mask_jwt(text)
        assert "***JWT_REDACTED***" in result
        assert "Bearer" in result

    def test_no_jwt(self) -> None:
        text = "no jwt here"
        assert _mask_jwt(text) == text

    def test_not_jwt_prefix(self) -> None:
        text = "eyXnotajwt"
        assert _mask_jwt(text) == text


# ===========================================================================
# _mask_url_params edge cases
# ===========================================================================


class TestMaskUrlParams:
    """Tests for URL sensitive parameter masking."""

    def test_token_param(self) -> None:
        url = "https://example.com/api?token=secret123"
        result = _mask_url_params(url)
        assert "?token=***REDACTED***" in result
        assert "secret123" not in result

    def test_api_key_param(self) -> None:
        url = "https://example.com/api?api_key=mykey123&other=safe"
        result = _mask_url_params(url)
        assert "?api_key=***REDACTED***" in result
        assert "mykey123" not in result
        assert "&other=safe" in result

    def test_multiple_sensitive_params(self) -> None:
        url = "https://example.com?token=abc&password=def&name=ok"
        result = _mask_url_params(url)
        assert "?token=***REDACTED***" in result
        assert "&password=***REDACTED***" in result
        assert "&name=ok" in result

    def test_case_insensitive(self) -> None:
        url = "https://example.com?TOKEN=abc"
        result = _mask_url_params(url)
        assert "abc" not in result

    def test_session_id_param(self) -> None:
        url = "https://example.com?session_id=xyz789"
        result = _mask_url_params(url)
        assert "xyz789" not in result

    def test_no_sensitive_params(self) -> None:
        url = "https://example.com?page=1&sort=name"
        assert _mask_url_params(url) == url


# ===========================================================================
# _mask_token_like edge cases
# ===========================================================================


class TestMaskTokenLike:
    """Tests for token-like string masking (>=20 chars alphanumeric)."""

    def test_19_chars_not_masked(self) -> None:
        token = "A" * 19
        assert _mask_token_like(token) == token

    def test_20_chars_masked(self) -> None:
        token = "A" * 20
        assert _mask_token_like(token) == "***REDACTED***"

    def test_long_token_masked(self) -> None:
        token = "abcdefghijklmnopqrstuvwxyz0123456789"
        assert _mask_token_like(token) == "***REDACTED***"

    def test_token_with_hyphens_underscores(self) -> None:
        token = "abc-def_ghi-jkl_mno-pqrs"  # 24 chars including - and _
        assert "***REDACTED***" in _mask_token_like(token)

    def test_mixed_text_and_token(self) -> None:
        text = f"Bearer {'x' * 30} is active"
        result = _mask_token_like(text)
        assert "***REDACTED***" in result
        assert "Bearer" in result

    def test_short_words_not_masked(self) -> None:
        text = "hello world foo bar"
        assert _mask_token_like(text) == text

    def test_spaces_break_token(self) -> None:
        """Spaces in the middle prevent a single long token match."""
        text = "aaaaaaaaaa bbbbbbbbbb"  # each 10 chars
        assert _mask_token_like(text) == text


# ===========================================================================
# _mask_value edge cases
# ===========================================================================


class TestMaskValue:
    """Tests for recursive _mask_value."""

    def test_sensitive_key_dict_redacted(self) -> None:
        data = {"api_token": "mysecretvalue"}
        result = _mask_value(data)
        assert result["api_token"] == "***REDACTED***"

    def test_password_key_redacted(self) -> None:
        result = _mask_value({"db_password": "hunter2"})
        assert result["db_password"] == "***REDACTED***"

    def test_nested_sensitive_key(self) -> None:
        data = {"config": {"authorization": "Bearer abc"}}
        result = _mask_value(data)
        assert result["config"]["authorization"] == "***REDACTED***"

    def test_list_values_masked(self) -> None:
        data = {"items": ["short", "A" * 25]}
        result = _mask_value(data)
        assert result["items"][0] == "short"
        assert result["items"][1] == "***REDACTED***"

    def test_tuple_values_masked(self) -> None:
        data = {"pair": ("short", "B" * 25)}
        result = _mask_value(data)
        assert isinstance(result["pair"], tuple)
        assert result["pair"][0] == "short"
        assert result["pair"][1] == "***REDACTED***"

    def test_non_string_scalar_passthrough(self) -> None:
        assert _mask_value(42) == 42
        assert _mask_value(True) is True
        assert _mask_value(None) is None

    def test_force_redacts_all_strings(self) -> None:
        assert _mask_value("anything", force=True) == "***REDACTED***"

    def test_ip_in_non_sensitive_key_masked(self) -> None:
        data = {"log_line": "Connection from 10.0.0.5"}
        result = _mask_value(data)
        assert "10.0.x.x" in result["log_line"]
    def test_ip_in_non_sensitive_key_masked(self) -> None:
        data = {"log_line": "Connection from 10.0.0.5"}
        result = _mask_value(data)
        assert "10.0.x.x" in result["log_line"]

    def test_ipv6_masked_in_value(self) -> None:
        data = {"source": "from 2001:db8:1:2:3:4:5:6"}
        result = _mask_value(data)
        assert "2001:db8:x:x:x:x:x:x" in result["source"]

    def test_jwt_masked_in_value(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        data = {"log": f"Token was {jwt}"}
        result = _mask_value(data)
        assert "***JWT_REDACTED***" in result["log"]

    def test_url_params_masked_in_value(self) -> None:
        data = {"url": "https://example.com?token=secret123&page=1"}
        result = _mask_value(data)
        assert "secret123" not in result["url"]
        assert "page=1" in result["url"]

    def test_cidr_masked_in_value(self) -> None:
        data = {"subnet": "10.0.0.0/24"}
        result = _mask_value(data)
        assert result["subnet"] == "10.0.x.x/24"
    def test_deeply_nested_sensitive(self) -> None:
        data = {"l1": {"l2": {"secret_key": "deep_value"}}}
        result = _mask_value(data)
        assert result["l1"]["l2"]["secret_key"] == "***REDACTED***"

    def test_empty_dict(self) -> None:
        assert _mask_value({}) == {}

    def test_empty_list(self) -> None:
        assert _mask_value([]) == []

    def test_empty_tuple(self) -> None:
        assert _mask_value(()) == ()

    def test_key_substring_match(self) -> None:
        """'my_api_key_id' contains 'key', so its value should be redacted."""
        data = {"my_api_key_id": "some_value"}
        result = _mask_value(data)
        assert result["my_api_key_id"] == "***REDACTED***"


# ===========================================================================
# redact_sensitive_processor
# ===========================================================================


class TestRedactSensitiveProcessor:
    """Tests for the structlog processor function."""

    def test_processor_redacts_event_dict(self) -> None:
        event_dict: dict[str, Any] = {
            "event": "login",
            "api_key": "secret123",
            "ip": "10.0.0.1",
        }
        result = redact_sensitive_processor(None, "info", event_dict)
        assert result["api_key"] == "***REDACTED***"
        assert "10.0.x.x" in result["ip"]

    def test_processor_preserves_non_sensitive(self) -> None:
        event_dict: dict[str, Any] = {"event": "startup", "level": "info"}
        result = redact_sensitive_processor(None, "info", event_dict)
        assert result["event"] == "startup"
        assert result["level"] == "info"


# ===========================================================================
# LoggingService singleton / idempotency
# ===========================================================================


class TestLoggingService:
    """Tests for LoggingService configure() and get_logger()."""

    def test_configure_sets_flag(self) -> None:
        LoggingService._configured = False
        svc = LoggingService(level="DEBUG")
        assert LoggingService._configured is True
        # Reset for isolation
        LoggingService._configured = False

    def test_configure_idempotent(self) -> None:
        LoggingService._configured = False
        svc = LoggingService(level="DEBUG")
        # Call again — should not raise or reconfigure
        svc.configure()
        assert LoggingService._configured is True
        LoggingService._configured = False

    def test_second_instance_does_not_reconfigure(self) -> None:
        LoggingService._configured = False
        _ = LoggingService(level="INFO")
        # _configured is True now; second instance skips configure
        svc2 = LoggingService(level="WARNING")
        # Level is stored as instance attr but configure was not called again
        assert svc2._level == "WARNING"
        assert LoggingService._configured is True
        LoggingService._configured = False

    def test_get_logger_returns_bound_logger(self) -> None:
        LoggingService._configured = False
        svc = LoggingService(level="INFO")
        logger = svc.get_logger("test_component")
        # Should be callable with structlog methods
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        LoggingService._configured = False

    def test_level_uppercased(self) -> None:
        LoggingService._configured = False
        svc = LoggingService(level="debug")
        assert svc._level == "DEBUG"
        LoggingService._configured = False

    def test_default_logger_name(self) -> None:
        LoggingService._configured = False
        svc = LoggingService()
        logger = svc.get_logger()
        # Default name parameter is "nocturna_engine" — logger should be created fine
        assert logger is not None
        LoggingService._configured = False
