"""Edge-case focused tests for nocturna_engine.models.target.Target."""

from __future__ import annotations

import json
from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError

from nocturna_engine.models.target import DOMAIN_PATTERN, Target


# ---------------------------------------------------------------------------
# model_validator: ensure_identifier
# ---------------------------------------------------------------------------


class TestEnsureIdentifier:
    """Both ip and domain missing must raise."""

    def test_missing_both_ip_and_domain_raises(self) -> None:
        with pytest.raises(ValidationError, match="Either 'ip' or 'domain' must be provided"):
            Target()

    def test_ip_only_is_valid(self) -> None:
        t = Target(ip="127.0.0.1")
        assert t.domain is None

    def test_domain_only_is_valid(self) -> None:
        t = Target(domain="example.com")
        assert t.ip is None

    def test_both_ip_and_domain_is_valid(self) -> None:
        t = Target(ip="10.0.0.1", domain="example.com")
        assert t.ip is not None and t.domain is not None

    def test_ip_none_and_domain_none_explicitly_raises(self) -> None:
        with pytest.raises(ValidationError, match="Either 'ip' or 'domain'"):
            Target(ip=None, domain=None)


# ---------------------------------------------------------------------------
# field_validator: normalize_domain
# ---------------------------------------------------------------------------


class TestNormalizeDomain:
    """Domain normalization edge cases."""

    def test_domain_lowercased(self) -> None:
        t = Target(domain="EXAMPLE.COM")
        assert t.domain == "example.com"

    def test_domain_stripped_of_whitespace(self) -> None:
        t = Target(domain="  example.com  ")
        assert t.domain == "example.com"

    def test_domain_mixed_case_and_whitespace(self) -> None:
        t = Target(domain="  Example.Org  ")
        assert t.domain == "example.org"

    def test_domain_exceeding_253_chars_raises(self) -> None:
        long_domain = ("a" * 63 + ".") * 3 + "a" * 60 + ".com"
        assert len(long_domain.strip().lower()) > 253
        with pytest.raises(ValidationError, match="253"):
            Target(domain=long_domain)

    def test_domain_exactly_253_chars_valid(self) -> None:
        # Build a domain that is exactly 253 characters and valid
        # a{63}.a{63}.a{63}.a{57}.com = 63+1+63+1+63+1+57+1+3 = 253
        parts = ["a" * 63, "a" * 63, "a" * 63, "a" * 57, "com"]
        domain = ".".join(parts)
        assert len(domain) == 253
        t = Target(domain=domain)
        assert t.domain == domain

    def test_empty_string_domain_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(domain="")

    def test_whitespace_only_domain_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(domain="   ")

    def test_domain_with_invalid_characters_raises(self) -> None:
        with pytest.raises(ValidationError, match="invalid"):
            Target(domain="exam ple.com")

    def test_domain_with_underscore_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(domain="ex_ample.com")

    def test_domain_single_label_raises(self) -> None:
        """A TLD-only string like 'localhost' doesn't match DOMAIN_PATTERN."""
        with pytest.raises(ValidationError, match="invalid"):
            Target(domain="localhost")

    def test_domain_with_trailing_dot_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(domain="example.com.")

    def test_domain_with_leading_hyphen_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(domain="-example.com")

    def test_domain_with_numeric_tld_raises(self) -> None:
        """TLD must be letters only per DOMAIN_PATTERN."""
        with pytest.raises(ValidationError):
            Target(domain="example.123")

    def test_domain_with_unicode_raises(self) -> None:
        """IDN (non-ascii) domains are not accepted by the ASCII pattern."""
        with pytest.raises(ValidationError):
            Target(domain="exämple.com")

    def test_domain_with_scheme_prefix_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(domain="https://example.com")


# ---------------------------------------------------------------------------
# field_validator: validate_scope_entries
# ---------------------------------------------------------------------------


class TestScopeValidation:
    """Scope entry validation edge cases."""

    def test_empty_scope_entry_raises(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            Target(ip="1.2.3.4", scope=[""])

    def test_whitespace_only_scope_entry_raises(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            Target(ip="1.2.3.4", scope=["   "])

    def test_valid_cidr_scope(self) -> None:
        t = Target(ip="10.0.0.1", scope=["10.0.0.0/8"])
        assert t.scope == ["10.0.0.0/8"]

    def test_valid_ipv6_cidr_scope(self) -> None:
        t = Target(ip="::1", scope=["fe80::/10"])
        assert t.scope == ["fe80::/10"]

    def test_valid_ip_scope_entry(self) -> None:
        t = Target(ip="1.1.1.1", scope=["192.168.1.1"])
        assert t.scope == ["192.168.1.1"]

    def test_valid_domain_scope_entry(self) -> None:
        t = Target(ip="1.1.1.1", scope=["example.com"])
        assert t.scope == ["example.com"]

    def test_invalid_cidr_scope_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(ip="1.1.1.1", scope=["999.999.999.999/33"])

    def test_invalid_domain_scope_entry_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid scope entry"):
            Target(ip="1.1.1.1", scope=["not a valid entry!!!"])

    def test_scope_entries_are_lowercased(self) -> None:
        t = Target(ip="1.1.1.1", scope=["EXAMPLE.COM"])
        assert t.scope == ["example.com"]

    def test_scope_entries_stripped(self) -> None:
        t = Target(ip="1.1.1.1", scope=["  10.0.0.0/24  "])
        assert t.scope == ["10.0.0.0/24"]

    def test_scope_domain_over_253_chars_raises(self) -> None:
        long = "a" * 254 + ".com"
        with pytest.raises(ValidationError, match="Invalid scope entry"):
            Target(ip="1.1.1.1", scope=[long])

    def test_scope_multiple_entries_mixed(self) -> None:
        t = Target(ip="1.1.1.1", scope=["10.0.0.0/24", "192.168.1.1", "example.com"])
        assert len(t.scope) == 3


# ---------------------------------------------------------------------------
# ConfigDict extra="forbid"
# ---------------------------------------------------------------------------


class TestExtraFieldsForbidden:
    """extra='forbid' must reject unknown fields."""

    def test_extra_field_raises(self) -> None:
        with pytest.raises(ValidationError, match="extra"):
            Target(ip="1.1.1.1", unknown_field="oops")

    def test_multiple_extra_fields_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(ip="1.1.1.1", foo="bar", baz=123)


# ---------------------------------------------------------------------------
# IP address edge cases
# ---------------------------------------------------------------------------


class TestIPEdgeCases:
    """IP address parsing boundary conditions."""

    def test_ipv4_loopback(self) -> None:
        t = Target(ip="127.0.0.1")
        assert t.ip == IPv4Address("127.0.0.1")

    def test_ipv6_loopback(self) -> None:
        t = Target(ip="::1")
        assert t.ip == IPv6Address("::1")

    def test_ipv6_full_form(self) -> None:
        t = Target(ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert t.ip is not None

    def test_ipv4_mapped_ipv6(self) -> None:
        t = Target(ip="::ffff:192.168.1.1")
        assert t.ip is not None

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(ip="999.999.999.999")

    def test_ip_as_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(ip="")

    def test_ip_as_hostname_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            Target(ip="not-an-ip")


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestTargetSerialization:
    """model_dump / model_validate / JSON round-trip."""

    def test_model_dump_contains_all_fields(self) -> None:
        t = Target(ip="1.1.1.1")
        d = t.model_dump()
        assert "ip" in d and "domain" in d and "scope" in d and "tags" in d and "metadata" in d

    def test_model_dump_ip_serialized_as_string(self) -> None:
        t = Target(ip="10.0.0.1")
        d = t.model_dump(mode="json")
        assert isinstance(d["ip"], str)

    def test_model_validate_round_trip(self) -> None:
        t = Target(ip="1.1.1.1", domain="example.com", tags=["web"])
        t2 = Target.model_validate(t.model_dump())
        assert t2.ip == t.ip and t2.domain == t.domain

    def test_model_validate_json_round_trip(self) -> None:
        t = Target(ip="1.1.1.1", domain="example.com")
        json_str = t.model_dump_json()
        t2 = Target.model_validate_json(json_str)
        assert t2.ip == t.ip and t2.domain == t.domain

    def test_metadata_preserved_through_serialization(self) -> None:
        t = Target(ip="1.1.1.1", metadata={"key": "value", "nested": {"a": 1}})
        t2 = Target.model_validate_json(t.model_dump_json())
        assert t2.metadata == {"key": "value", "nested": {"a": 1}}


# ---------------------------------------------------------------------------
# Tags & metadata edge cases
# ---------------------------------------------------------------------------


class TestTagsAndMetadata:
    """Tags list and metadata dict boundary values."""

    def test_empty_tags_default(self) -> None:
        t = Target(ip="1.1.1.1")
        assert t.tags == []

    def test_empty_metadata_default(self) -> None:
        t = Target(ip="1.1.1.1")
        assert t.metadata == {}

    def test_unicode_tags(self) -> None:
        t = Target(ip="1.1.1.1", tags=["日本語", "🔒"])
        assert len(t.tags) == 2

    def test_metadata_with_none_values(self) -> None:
        t = Target(ip="1.1.1.1", metadata={"key": None})
        assert t.metadata["key"] is None


# ---------------------------------------------------------------------------
# validate_assignment=True
# ---------------------------------------------------------------------------


class TestValidateAssignment:
    """Assigning invalid values after construction must raise."""

    def test_assigning_invalid_domain_raises(self) -> None:
        t = Target(ip="1.1.1.1", domain="example.com")
        with pytest.raises(ValidationError):
            t.domain = "not valid!!"

    def test_assigning_valid_domain_succeeds(self) -> None:
        t = Target(ip="1.1.1.1", domain="example.com")
        t.domain = "newdomain.org"
        assert t.domain == "newdomain.org"

    def test_assigning_invalid_ip_raises(self) -> None:
        t = Target(ip="1.1.1.1")
        with pytest.raises(ValidationError):
            t.ip = "bad"


# ---------------------------------------------------------------------------
# Parametrized: invalid domains
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_domain",
    [
        "",
        " ",
        ".",
        ".com",
        "com.",
        "-bad.com",
        "bad-.com",
        "a" * 64 + ".com",  # label > 63 chars
        "ex ample.com",
        "example..com",
        "123.456",
        "http://foo.com",
    ],
    ids=[
        "empty",
        "whitespace",
        "dot_only",
        "leading_dot",
        "trailing_dot",
        "leading_hyphen",
        "trailing_hyphen_label",
        "label_too_long",
        "space_in_domain",
        "double_dot",
        "numeric_tld",
        "scheme_prefix",
    ],
)
def test_parametrized_invalid_domains(bad_domain: str) -> None:
    with pytest.raises(ValidationError):
        Target(domain=bad_domain)


@pytest.mark.parametrize(
    "good_domain",
    [
        "example.com",
        "sub.example.co",
        "a.bc",
        "x-y.example.org",
        "a1b2.example.com",
    ],
    ids=["basic", "subdomain", "min_tld", "hyphened", "alphanumeric"],
)
def test_parametrized_valid_domains(good_domain: str) -> None:
    t = Target(domain=good_domain)
    assert t.domain == good_domain.lower()
