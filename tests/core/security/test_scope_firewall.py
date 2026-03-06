"""Comprehensive edge-case tests for the scope firewall security module."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

import pytest

from nocturna_engine.core.security import (
    SCOPE_REASON_DENIED,
    SCOPE_REASON_INVALID_TARGET,
    SCOPE_REASON_KILL_SWITCH,
    ScopeFirewall,
    ScopeFirewallDecision,
)
from nocturna_engine.models.target import Target


# ---------------------------------------------------------------------------
# Constants sanity
# ---------------------------------------------------------------------------


class TestConstants:
    """Verify exported reason constants have stable string values."""

    def test_scope_reason_denied_value(self) -> None:
        assert SCOPE_REASON_DENIED == "scope_denied"

    def test_scope_reason_invalid_target_value(self) -> None:
        assert SCOPE_REASON_INVALID_TARGET == "scope_invalid_target"

    def test_scope_reason_kill_switch_value(self) -> None:
        assert SCOPE_REASON_KILL_SWITCH == "scope_kill_switch"

    def test_constants_are_strings(self) -> None:
        for const in (SCOPE_REASON_DENIED, SCOPE_REASON_INVALID_TARGET, SCOPE_REASON_KILL_SWITCH):
            assert isinstance(const, str)


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


class TestKillSwitch:
    """Kill switch must block everything, regardless of allow/deny rules."""

    def test_kill_switch_blocks_valid_host(self) -> None:
        fw = ScopeFirewall.from_mapping({"kill_switch": True})
        d = fw.evaluate_target("example.com")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_KILL_SWITCH

    def test_kill_switch_blocks_valid_ip(self) -> None:
        fw = ScopeFirewall.from_mapping({"kill_switch": True})
        d = fw.evaluate_target("10.0.0.1")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_KILL_SWITCH

    def test_kill_switch_blocks_ipv6(self) -> None:
        fw = ScopeFirewall.from_mapping({"kill_switch": True, "allowlist_cidrs": ["::/0"]})
        d = fw.evaluate_target("::1")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_KILL_SWITCH

    def test_kill_switch_blocks_cidr(self) -> None:
        fw = ScopeFirewall.from_mapping({"kill_switch": True})
        d = fw.evaluate_target("192.168.0.0/24")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_KILL_SWITCH

    def test_kill_switch_overrides_allowlist(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "kill_switch": True,
            "allowlist_hosts": ["example.com"],
            "allowlist_cidrs": ["0.0.0.0/0"],
        })
        assert fw.evaluate_target("example.com").allowed is False
        assert fw.evaluate_target("1.2.3.4").allowed is False

    def test_kill_switch_still_normalizes_target(self) -> None:
        fw = ScopeFirewall.from_mapping({"kill_switch": True})
        d = fw.evaluate_target("EXAMPLE.COM")
        assert d.normalized_target == "example.com"

    def test_kill_switch_with_invalid_target_still_reports_kill_switch(self) -> None:
        fw = ScopeFirewall.from_mapping({"kill_switch": True})
        d = fw.evaluate_target("http://bad host/path")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_KILL_SWITCH
        assert d.normalized_target is None

    def test_kill_switch_false_does_not_block(self) -> None:
        fw = ScopeFirewall.from_mapping({"kill_switch": False})
        assert fw.evaluate_target("example.com").allowed is True


# ---------------------------------------------------------------------------
# Allowlist-only mode
# ---------------------------------------------------------------------------


class TestAllowlistOnly:
    """When only allowlist is set, unlisted targets are denied."""

    def test_host_in_allowlist_passes(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["example.com"]})
        assert fw.evaluate_target("example.com").allowed is True

    def test_subdomain_of_allowlisted_host_passes(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["example.com"]})
        assert fw.evaluate_target("api.example.com").allowed is True

    def test_host_not_in_allowlist_denied(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["example.com"]})
        d = fw.evaluate_target("evil.com")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_ip_in_allowlist_cidr_passes(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/24"]})
        assert fw.evaluate_target("10.0.0.100").allowed is True

    def test_ip_outside_allowlist_cidr_denied(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/24"]})
        d = fw.evaluate_target("10.0.1.1")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_ip_in_host_allowlist_passes(self) -> None:
        """An IP literal in allowlist_hosts should match via _ip_matches_host_rules."""
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["192.168.1.1"]})
        assert fw.evaluate_target("192.168.1.1").allowed is True

    def test_cidr_target_in_allowlist_cidr_passes(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/8"]})
        assert fw.evaluate_target("10.1.0.0/16").allowed is True

    def test_cidr_target_not_subnet_of_allowlist_denied(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/24"]})
        d = fw.evaluate_target("10.0.0.0/16")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED


# ---------------------------------------------------------------------------
# Denylist-only mode
# ---------------------------------------------------------------------------


class TestDenylistOnly:
    """When only denylist is set and no allowlist, unlisted targets pass."""

    def test_host_in_denylist_blocked(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_hosts": ["evil.com"]})
        d = fw.evaluate_target("evil.com")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_subdomain_of_denylisted_host_blocked(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_hosts": ["evil.com"]})
        d = fw.evaluate_target("api.evil.com")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_host_not_in_denylist_passes(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_hosts": ["evil.com"]})
        assert fw.evaluate_target("good.com").allowed is True

    def test_ip_in_denylist_cidr_blocked(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_cidrs": ["192.168.0.0/16"]})
        d = fw.evaluate_target("192.168.10.5")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_ip_outside_denylist_passes(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_cidrs": ["192.168.0.0/16"]})
        assert fw.evaluate_target("10.0.0.1").allowed is True

    def test_cidr_target_overlapping_denylist_blocked(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_cidrs": ["10.0.0.0/24"]})
        d = fw.evaluate_target("10.0.0.0/28")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED


# ---------------------------------------------------------------------------
# Mixed allow + deny
# ---------------------------------------------------------------------------


class TestMixedAllowDeny:
    """Denylist takes precedence over allowlist."""

    def test_deny_overrides_allow_for_host(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_hosts": ["example.com"],
            "denylist_hosts": ["example.com"],
        })
        d = fw.evaluate_target("example.com")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_deny_overrides_allow_for_ip(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_cidrs": ["10.0.0.0/8"],
            "denylist_cidrs": ["10.0.0.5/32"],
        })
        d = fw.evaluate_target("10.0.0.5")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_allowed_ip_not_in_deny_passes(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_cidrs": ["10.0.0.0/8"],
            "denylist_cidrs": ["10.0.0.5/32"],
        })
        assert fw.evaluate_target("10.0.0.6").allowed is True

    def test_ip_denied_via_host_rule_in_denylist(self) -> None:
        """IP in denylist_hosts should block the IP target."""
        fw = ScopeFirewall.from_mapping({
            "allowlist_cidrs": ["0.0.0.0/0"],
            "denylist_hosts": ["10.0.0.5"],
        })
        d = fw.evaluate_target("10.0.0.5")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED

    def test_deny_subdomain_but_allow_parent(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_hosts": ["example.com"],
            "denylist_hosts": ["secret.example.com"],
        })
        assert fw.evaluate_target("api.example.com").allowed is True
        assert fw.evaluate_target("secret.example.com").allowed is False

    def test_cidr_target_overlapping_denylist_blocked_even_with_allowlist(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_cidrs": ["10.0.0.0/8"],
            "denylist_cidrs": ["10.0.1.0/24"],
        })
        d = fw.evaluate_target("10.0.1.0/28")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED


# ---------------------------------------------------------------------------
# CIDR matching edge cases
# ---------------------------------------------------------------------------


class TestCidrMatching:
    """Boundary conditions for CIDR/IP matching."""

    @pytest.mark.parametrize(
        "cidr,ip,expected",
        [
            ("10.0.0.0/32", "10.0.0.0", True),
            ("10.0.0.0/32", "10.0.0.1", False),
            ("0.0.0.0/0", "255.255.255.255", True),
            ("0.0.0.0/0", "1.2.3.4", True),
            ("192.168.1.0/24", "192.168.1.0", True),
            ("192.168.1.0/24", "192.168.1.255", True),
            ("192.168.1.0/24", "192.168.2.0", False),
        ],
        ids=[
            "slash32-exact-match",
            "slash32-off-by-one",
            "slash0-catches-all-max",
            "slash0-catches-all-random",
            "slash24-network-addr",
            "slash24-broadcast",
            "slash24-out-of-range",
        ],
    )
    def test_ipv4_cidr_boundary(self, cidr: str, ip: str, expected: bool) -> None:
        if expected:
            fw = ScopeFirewall.from_mapping({"allowlist_cidrs": [cidr]})
            assert fw.evaluate_target(ip).allowed is True
        else:
            fw = ScopeFirewall.from_mapping({"allowlist_cidrs": [cidr]})
            d = fw.evaluate_target(ip)
            assert d.allowed is False

    @pytest.mark.parametrize(
        "cidr,ip,expected",
        [
            ("::/0", "::1", True),
            ("::/0", "2001:db8::1", True),
            ("2001:db8::/32", "2001:db8::1", True),
            ("2001:db8::/32", "2001:db9::1", False),
            ("::1/128", "::1", True),
            ("::1/128", "::2", False),
        ],
        ids=[
            "ipv6-slash0-loopback",
            "ipv6-slash0-global",
            "ipv6-slash32-in",
            "ipv6-slash32-out",
            "ipv6-slash128-exact",
            "ipv6-slash128-off-by-one",
        ],
    )
    def test_ipv6_cidr_boundary(self, cidr: str, ip: str, expected: bool) -> None:
        if expected:
            fw = ScopeFirewall.from_mapping({"allowlist_cidrs": [cidr]})
            assert fw.evaluate_target(ip).allowed is True
        else:
            fw = ScopeFirewall.from_mapping({"allowlist_cidrs": [cidr]})
            d = fw.evaluate_target(ip)
            assert d.allowed is False

    def test_ipv4_in_ipv6_cidr_does_not_match(self) -> None:
        """IPv4 address should never match an IPv6 CIDR (version mismatch)."""
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["::/0"]})
        d = fw.evaluate_target("10.0.0.1")
        assert d.allowed is False

    def test_ipv6_in_ipv4_cidr_does_not_match(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["0.0.0.0/0"]})
        d = fw.evaluate_target("::1")
        assert d.allowed is False

    def test_overlapping_cidrs_in_denylist(self) -> None:
        """Overlapping deny CIDRs: both /24 and /16 deny, IP in /24 is blocked."""
        fw = ScopeFirewall.from_mapping({
            "denylist_cidrs": ["10.0.0.0/16", "10.0.1.0/24"],
        })
        d = fw.evaluate_target("10.0.1.50")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_DENIED


# ---------------------------------------------------------------------------
# Host matching edge cases
# ---------------------------------------------------------------------------


class TestHostMatching:
    """Host matching: case insensitivity, suffix matching, edge cases."""

    def test_case_insensitive_host(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["EXAMPLE.COM"]})
        assert fw.evaluate_target("example.com").allowed is True

    def test_mixed_case_input(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["example.com"]})
        assert fw.evaluate_target("EXAMPLE.COM").allowed is True

    def test_trailing_dot_is_stripped(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["example.com."]})
        assert fw.evaluate_target("example.com").allowed is True

    def test_host_suffix_matching_does_not_match_partial_label(self) -> None:
        """notexample.com should NOT match allowlist entry 'example.com'."""
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["example.com"]})
        d = fw.evaluate_target("notexample.com")
        assert d.allowed is False

    def test_idna_encoded_host_matching(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["xn--bcher-kva.de"]})
        d = fw.evaluate_target("xn--bcher-kva.de")
        assert d.allowed is True
        assert d.normalized_target == "xn--bcher-kva.de"

    def test_single_label_host_in_allowlist(self) -> None:
        """Single label hostnames should be normalizable."""
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["localhost"]})
        assert fw.evaluate_target("localhost").allowed is True


# ---------------------------------------------------------------------------
# Loopback and special addresses
# ---------------------------------------------------------------------------


class TestSpecialAddresses:
    """Loopback, private, link-local addresses."""

    def test_ipv4_loopback_allowed_when_no_rules(self) -> None:
        fw = ScopeFirewall.from_mapping({})
        assert fw.evaluate_target("127.0.0.1").allowed is True

    def test_ipv6_loopback_allowed_when_no_rules(self) -> None:
        fw = ScopeFirewall.from_mapping({})
        assert fw.evaluate_target("::1").allowed is True

    def test_ipv4_loopback_blocked_by_denylist(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_cidrs": ["127.0.0.0/8"]})
        d = fw.evaluate_target("127.0.0.1")
        assert d.allowed is False

    def test_ipv6_loopback_blocked_by_denylist(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_cidrs": ["::1/128"]})
        d = fw.evaluate_target("::1")
        assert d.allowed is False

    def test_private_ip_allowed_when_no_rules(self) -> None:
        fw = ScopeFirewall.from_mapping({})
        assert fw.evaluate_target("192.168.1.1").allowed is True

    def test_private_ip_blocked_by_denylist(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_cidrs": ["192.168.0.0/16"]})
        d = fw.evaluate_target("192.168.1.1")
        assert d.allowed is False


# ---------------------------------------------------------------------------
# Empty rulesets and backward compatibility
# ---------------------------------------------------------------------------


class TestEmptyRulesets:
    """Empty/missing rules should not restrict traffic (backward compat)."""

    def test_empty_mapping_allows_all_hosts(self) -> None:
        fw = ScopeFirewall.from_mapping({})
        assert fw.evaluate_target("any.host.com").allowed is True

    def test_empty_mapping_allows_all_ips(self) -> None:
        fw = ScopeFirewall.from_mapping({})
        assert fw.evaluate_target("8.8.8.8").allowed is True

    def test_none_mapping_allows_all(self) -> None:
        fw = ScopeFirewall.from_mapping(None)
        assert fw.evaluate_target("example.com").allowed is True

    def test_empty_allowlist_hosts_does_not_restrict(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": []})
        assert fw.evaluate_target("example.com").allowed is True

    def test_empty_allowlist_cidrs_does_not_restrict(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": []})
        assert fw.evaluate_target("10.0.0.1").allowed is True

    def test_empty_denylist_does_not_block(self) -> None:
        fw = ScopeFirewall.from_mapping({"denylist_hosts": [], "denylist_cidrs": []})
        assert fw.evaluate_target("example.com").allowed is True


# ---------------------------------------------------------------------------
# Invalid target inputs
# ---------------------------------------------------------------------------


class TestInvalidTargets:
    """Various invalid/malformed targets produce SCOPE_REASON_INVALID_TARGET."""

    @pytest.mark.parametrize(
        "target",
        [
            "",
            "   ",
            "http://bad host/path",
            "-invalid-host.com",
        ],
        ids=["empty-string", "whitespace-only", "url-with-spaces", "leading-hyphen"],
    )
    def test_invalid_string_target(self, target: str) -> None:
        fw = ScopeFirewall.from_mapping({})
        d = fw.evaluate_target(target)
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_INVALID_TARGET

    def test_invalid_cidr_string(self) -> None:
        fw = ScopeFirewall.from_mapping({})
        d = fw.evaluate_target("not-a-cidr/33")
        assert d.allowed is False
        assert d.reason_code == SCOPE_REASON_INVALID_TARGET


# ---------------------------------------------------------------------------
# Domain vs IP detection
# ---------------------------------------------------------------------------


class TestDomainVsIpDetection:
    """Ensure the firewall correctly distinguishes hosts, IPs, CIDRs."""

    def test_ipv4_string_detected_as_ip(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/8"]})
        d = fw.evaluate_target("10.0.0.1")
        assert d.allowed is True
        assert d.normalized_target == "10.0.0.1"

    def test_ipv6_string_detected_as_ip(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["2001:db8::/32"]})
        d = fw.evaluate_target("2001:db8::1")
        assert d.allowed is True

    def test_cidr_string_detected_as_cidr(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/8"]})
        d = fw.evaluate_target("10.1.0.0/16")
        assert d.allowed is True

    def test_hostname_with_hyphens_detected_as_host(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["my-host.example.com"]})
        assert fw.evaluate_target("my-host.example.com").allowed is True

    def test_ipv4_object_accepted(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/8"]})
        d = fw.evaluate_target(IPv4Address("10.0.0.1"))
        assert d.allowed is True

    def test_ipv6_object_accepted(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["2001:db8::/32"]})
        d = fw.evaluate_target(IPv6Address("2001:db8::1"))
        assert d.allowed is True

    def test_ipv4_network_object_accepted(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/8"]})
        d = fw.evaluate_target(IPv4Network("10.1.0.0/16"))
        assert d.allowed is True

    def test_ipv6_network_object_accepted(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["2001:db8::/32"]})
        d = fw.evaluate_target(IPv6Network("2001:db8:1::/48"))
        assert d.allowed is True


# ---------------------------------------------------------------------------
# Target model input
# ---------------------------------------------------------------------------


class TestTargetModelInput:
    """Evaluate targets using the Target pydantic model."""

    def test_target_with_domain(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["example.com"]})
        t = Target(domain="example.com")
        assert fw.evaluate_target(t).allowed is True

    def test_target_with_ip(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["10.0.0.0/8"]})
        t = Target(ip="10.0.0.1")
        assert fw.evaluate_target(t).allowed is True

    def test_target_with_only_domain_none_and_ip_none_fails_pydantic(self) -> None:
        """Target model requires at least one identifier."""
        with pytest.raises(Exception):
            Target()


# ---------------------------------------------------------------------------
# from_mapping() factory edge cases
# ---------------------------------------------------------------------------


class TestFromMapping:
    """Test the from_mapping factory with various config shapes."""

    def test_none_input(self) -> None:
        fw = ScopeFirewall.from_mapping(None)
        assert fw.kill_switch is False
        assert fw.allowlist_hosts == ()
        assert fw.allowlist_cidrs == ()
        assert fw.denylist_hosts == ()
        assert fw.denylist_cidrs == ()

    def test_empty_dict(self) -> None:
        fw = ScopeFirewall.from_mapping({})
        assert fw.kill_switch is False
        assert fw.allowlist_hosts == ()

    def test_none_values_in_keys(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_hosts": None,
            "allowlist_cidrs": None,
            "denylist_hosts": None,
            "denylist_cidrs": None,
            "kill_switch": None,
        })
        assert fw.kill_switch is False
        assert fw.allowlist_hosts == ()

    def test_string_instead_of_list_for_hosts(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": "example.com"})
        assert fw.allowlist_hosts == ("example.com",)

    def test_string_instead_of_list_for_cidrs(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": "10.0.0.0/8"})
        assert len(fw.allowlist_cidrs) == 1
        assert fw.allowlist_cidrs[0] == ip_network("10.0.0.0/8")

    def test_duplicate_hosts_are_deduplicated(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_hosts": ["example.com", "EXAMPLE.COM", "example.com"],
        })
        assert fw.allowlist_hosts == ("example.com",)

    def test_duplicate_cidrs_are_deduplicated(self) -> None:
        fw = ScopeFirewall.from_mapping({
            "allowlist_cidrs": ["10.0.0.0/8", "10.0.0.0/8"],
        })
        assert len(fw.allowlist_cidrs) == 1

    def test_invalid_cidr_is_silently_skipped(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_cidrs": ["not-a-cidr", "10.0.0.0/8"]})
        assert len(fw.allowlist_cidrs) == 1
        assert fw.allowlist_cidrs[0] == ip_network("10.0.0.0/8")

    def test_invalid_host_is_silently_skipped(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": ["-bad-", "example.com"]})
        assert fw.allowlist_hosts == ("example.com",)

    def test_none_items_in_list_are_skipped(self) -> None:
        fw = ScopeFirewall.from_mapping({"allowlist_hosts": [None, "example.com", None]})
        assert fw.allowlist_hosts == ("example.com",)

    def test_kill_switch_truthy_values(self) -> None:
        for truthy in (True, 1, "yes"):
            fw = ScopeFirewall.from_mapping({"kill_switch": truthy})
            assert fw.kill_switch is True


# ---------------------------------------------------------------------------
# from_runtime() and _extract_rules_payload
# ---------------------------------------------------------------------------


class TestFromRuntime:
    """Test nested config extraction via from_runtime."""

    def test_flat_keys_at_top_level(self) -> None:
        fw = ScopeFirewall.from_runtime(config={
            "kill_switch": True,
            "allowlist_hosts": ["example.com"],
        })
        assert fw.kill_switch is True
        assert fw.allowlist_hosts == ("example.com",)

    def test_nested_under_scope_firewall(self) -> None:
        fw = ScopeFirewall.from_runtime(config={
            "scope_firewall": {
                "denylist_hosts": ["evil.com"],
            }
        })
        assert fw.denylist_hosts == ("evil.com",)

    def test_nested_under_security_scope_firewall(self) -> None:
        fw = ScopeFirewall.from_runtime(config={
            "security": {
                "scope_firewall": {
                    "denylist_hosts": ["evil.com"],
                }
            }
        })
        assert fw.denylist_hosts == ("evil.com",)

    def test_policy_overrides_config(self) -> None:
        fw = ScopeFirewall.from_runtime(
            config={"kill_switch": False},
            policy={"kill_switch": True},
        )
        assert fw.kill_switch is True

    def test_none_config_and_policy(self) -> None:
        fw = ScopeFirewall.from_runtime(config=None, policy=None)
        assert fw.kill_switch is False
        assert fw.allowlist_hosts == ()

    def test_extract_rules_with_mixed_known_and_unknown_keys(self) -> None:
        fw = ScopeFirewall.from_runtime(config={
            "kill_switch": True,
            "unknown_key": "ignored",
        })
        assert fw.kill_switch is True


# ---------------------------------------------------------------------------
# ScopeFirewallDecision model
# ---------------------------------------------------------------------------


class TestScopeFirewallDecision:
    """Validate the decision dataclass."""

    def test_decision_is_frozen(self) -> None:
        d = ScopeFirewallDecision(allowed=True)
        with pytest.raises(AttributeError):
            d.allowed = False  # type: ignore[misc]

    def test_decision_defaults(self) -> None:
        d = ScopeFirewallDecision(allowed=True)
        assert d.reason is None
        assert d.reason_code is None
        assert d.normalized_target is None

    def test_decision_full_fields(self) -> None:
        d = ScopeFirewallDecision(
            allowed=False,
            reason="test",
            reason_code=SCOPE_REASON_DENIED,
            normalized_target="example.com",
        )
        assert d.allowed is False
        assert d.reason == "test"
        assert d.reason_code == SCOPE_REASON_DENIED
        assert d.normalized_target == "example.com"
