"""Edge-case tests for PluginPolicyEngine, PluginPolicy model, egress evaluation."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from nocturna_engine.core.plugin_v2.contracts import (
    ExecutionRequirements,
    PluginManifest,
)
from nocturna_engine.core.plugin_v2.policy.constants import (
    POLICY_REASON_DENIED_EGRESS_CIDR,
    POLICY_REASON_DENIED_EGRESS_HOST,
    POLICY_REASON_DENIED_EGRESS_PORT,
    POLICY_REASON_DENIED_EGRESS_PROTOCOL,
    POLICY_REASON_DENIED_FILESYSTEM,
    POLICY_REASON_DENIED_NETWORK,
    POLICY_REASON_DENIED_SUBPROCESS,
    POLICY_REASON_INVALID,
)
from nocturna_engine.core.plugin_v2.policy.egress.evaluator import EgressPolicyEvaluator
from nocturna_engine.core.plugin_v2.policy.egress.normalization import (
    normalize_host,
    normalize_ip,
    normalize_protocol,
    split_endpoint_text,
    try_normalize_port,
)
from nocturna_engine.core.plugin_v2.policy.egress.parsing import parse_host_rule, parse_host_rules
from nocturna_engine.core.plugin_v2.policy.engine import PluginPolicyEngine
from nocturna_engine.core.plugin_v2.policy.models import (
    EgressDecision,
    EgressEndpoint,
    PluginPolicy,
    PolicyBuildResult,
    PolicyDecision,
)


# ---------------------------------------------------------------------------
# PluginPolicy model validation
# ---------------------------------------------------------------------------

async def test_policy_defaults():
    policy = PluginPolicy()
    assert policy.allow_subprocess is False
    assert policy.allow_network is False
    assert policy.allow_filesystem is False
    assert policy.default_egress_action == "deny"
    assert policy.allow_cache is True
    assert policy.circuit_breaker_threshold == 3
    assert policy.strict_quarantine is False


async def test_policy_extra_fields_forbidden():
    with pytest.raises(Exception):
        PluginPolicy(unknown_field="bad")  # type: ignore[call-arg]


async def test_policy_negative_timeout_rejected():
    with pytest.raises(Exception):
        PluginPolicy(max_timeout_seconds=-1.0)


async def test_policy_zero_timeout_rejected():
    with pytest.raises(Exception):
        PluginPolicy(max_timeout_seconds=0)


async def test_policy_negative_output_bytes_rejected():
    with pytest.raises(Exception):
        PluginPolicy(max_output_bytes=-1)


async def test_policy_retries_out_of_range():
    with pytest.raises(Exception):
        PluginPolicy(max_retries=99)


async def test_policy_valid_egress_hosts():
    policy = PluginPolicy(egress_allow_hosts=["Example.COM", " api.example.com "])
    assert "example.com" in policy.egress_allow_hosts
    assert "api.example.com" in policy.egress_allow_hosts


async def test_policy_egress_hosts_from_string():
    policy = PluginPolicy(egress_allow_hosts="single.host")  # type: ignore[arg-type]
    assert policy.egress_allow_hosts == ("single.host",)


async def test_policy_egress_hosts_none_becomes_empty():
    policy = PluginPolicy(egress_allow_hosts=None)  # type: ignore[arg-type]
    assert policy.egress_allow_hosts == ()


async def test_policy_egress_cidrs_normalized():
    policy = PluginPolicy(egress_allow_cidrs=["10.0.0.0/8"])
    assert "10.0.0.0/8" in policy.egress_allow_cidrs


async def test_policy_egress_cidrs_strict_false():
    """Non-strict CIDR like 10.0.0.5/8 should be normalized to 10.0.0.0/8."""
    policy = PluginPolicy(egress_allow_cidrs=["10.0.0.5/8"])
    assert "10.0.0.0/8" in policy.egress_allow_cidrs


async def test_policy_egress_cidrs_invalid_rejected():
    with pytest.raises(Exception):
        PluginPolicy(egress_allow_cidrs=["not_a_cidr"])


async def test_policy_egress_ports_valid():
    policy = PluginPolicy(egress_allow_ports=[80, 443])
    assert 80 in policy.egress_allow_ports


async def test_policy_egress_ports_out_of_range():
    with pytest.raises(Exception):
        PluginPolicy(egress_allow_ports=[0])

    with pytest.raises(Exception):
        PluginPolicy(egress_allow_ports=[70000])


async def test_policy_egress_ports_from_single_int():
    policy = PluginPolicy(egress_allow_ports=443)  # type: ignore[arg-type]
    assert policy.egress_allow_ports == (443,)


async def test_policy_egress_protocols_normalized():
    policy = PluginPolicy(egress_allow_protocols=["HTTPS", " http "])
    assert "https" in policy.egress_allow_protocols
    assert "http" in policy.egress_allow_protocols


async def test_policy_has_egress_rules_default_deny():
    """Default policy has deny egress action, so egress rules are active."""
    policy = PluginPolicy()
    assert policy.has_egress_rules() is True


async def test_policy_has_egress_rules_with_deny():
    policy = PluginPolicy(default_egress_action="deny")
    assert policy.has_egress_rules() is True


async def test_policy_has_egress_rules_with_hosts():
    policy = PluginPolicy(egress_deny_hosts=["evil.com"])
    assert policy.has_egress_rules() is True


# ---------------------------------------------------------------------------
# PluginPolicyEngine – build_policy / build_policy_result
# ---------------------------------------------------------------------------

async def test_engine_build_policy_default():
    engine = PluginPolicyEngine()
    policy = engine.build_policy()
    assert policy.allow_network is False


async def test_engine_build_policy_with_override():
    engine = PluginPolicyEngine()
    policy = engine.build_policy({"allow_network": False})
    assert policy.allow_network is False


async def test_engine_build_policy_result_none_payload():
    engine = PluginPolicyEngine()
    result = engine.build_policy_result(None)
    assert result.valid is True
    assert result.policy.allow_network is False


async def test_engine_build_policy_result_valid():
    engine = PluginPolicyEngine()
    result = engine.build_policy_result({"allow_cache": False})
    assert result.valid is True
    assert result.policy.allow_cache is False


async def test_engine_build_policy_result_invalid_fail_closed():
    engine = PluginPolicyEngine()
    result = engine.build_policy_result({"max_timeout_seconds": -5}, fail_closed=True)
    assert result.valid is False
    assert result.reason_code == POLICY_REASON_INVALID
    assert result.error is not None


async def test_engine_build_policy_result_invalid_fail_open():
    engine = PluginPolicyEngine()
    result = engine.build_policy_result({"max_timeout_seconds": -5}, fail_closed=False)
    assert result.valid is True  # fail-open keeps valid=True
    assert result.reason_code == POLICY_REASON_INVALID
    assert result.error is not None

async def test_engine_build_policy_result_merge():
    """Override should merge with defaults; unspecified fields keep defaults."""
    engine = PluginPolicyEngine()
    result = engine.build_policy_result({"allow_filesystem": False})
    assert result.policy.allow_filesystem is False
    assert result.policy.allow_network is False  # kept default


async def test_engine_build_policy_result_empty_payload():
    engine = PluginPolicyEngine()
    result = engine.build_policy_result({})
    assert result.valid is True
    # All defaults preserved
    assert result.policy.allow_network is False


# ---------------------------------------------------------------------------
# PluginPolicyEngine – evaluate
# ---------------------------------------------------------------------------

def _manifest(*, subprocess: bool = False, network: bool = False, filesystem: bool = False) -> PluginManifest:
    return PluginManifest(
        id="test_tool",
        display_name="Test Tool",
        execution_requirements=ExecutionRequirements(
            subprocess=subprocess, network=network, filesystem=filesystem,
        ),
    )


async def test_engine_evaluate_allows_all():
    engine = PluginPolicyEngine()
    decision = engine.evaluate(_manifest(), PluginPolicy())
    assert decision.allowed is True


async def test_engine_evaluate_denies_subprocess():
    engine = PluginPolicyEngine()
    decision = engine.evaluate(
        _manifest(subprocess=True),
        PluginPolicy(allow_subprocess=False),
    )
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_SUBPROCESS


async def test_engine_evaluate_denies_network():
    engine = PluginPolicyEngine()
    decision = engine.evaluate(
        _manifest(network=True),
        PluginPolicy(allow_network=False),
    )
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_NETWORK


async def test_engine_evaluate_denies_filesystem():
    engine = PluginPolicyEngine()
    decision = engine.evaluate(
        _manifest(filesystem=True),
        PluginPolicy(allow_filesystem=False),
    )
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_FILESYSTEM


async def test_engine_evaluate_effective_timeout():
    engine = PluginPolicyEngine()
    manifest = PluginManifest(
        id="t", display_name="T",
        execution_requirements=ExecutionRequirements(max_timeout_seconds=60.0),
    )
    decision = engine.evaluate(manifest, PluginPolicy(max_timeout_seconds=30.0))
    assert decision.allowed is True
    assert decision.effective_timeout_seconds == 30.0


async def test_engine_evaluate_effective_output_bytes():
    engine = PluginPolicyEngine()
    manifest = PluginManifest(
        id="t", display_name="T",
        execution_requirements=ExecutionRequirements(max_output_bytes=1000),
    )
    decision = engine.evaluate(manifest, PluginPolicy(max_output_bytes=500))
    assert decision.allowed is True
    assert decision.effective_max_output_bytes == 500


async def test_engine_evaluate_effective_retries():
    engine = PluginPolicyEngine()
    decision = engine.evaluate(_manifest(), PluginPolicy(max_retries=2))
    assert decision.effective_retries == 2


async def test_engine_invalid_policy_decision():
    engine = PluginPolicyEngine()
    decision = engine.invalid_policy_decision()
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_INVALID


async def test_engine_evaluate_manifest_payload():
    engine = PluginPolicyEngine()
    manifest = _manifest(network=True)
    payload = manifest.machine_readable(include_schema=True)
    payload["implementation"] = {"class_name": "Test"}  # Should be stripped
    decision = engine.evaluate_manifest_payload(payload, PluginPolicy(allow_network=False))
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_NETWORK


# ---------------------------------------------------------------------------
# Egress normalization helpers
# ---------------------------------------------------------------------------

async def test_normalize_host_basic():
    assert normalize_host("Example.COM") == "example.com"
    assert normalize_host(" host. ") == "host"  # trailing dot stripped
    assert normalize_host(None) is None
    assert normalize_host("") is None
    assert normalize_host("[::1]") == "::1"


async def test_normalize_ip_valid_ipv4():
    ip = normalize_ip("192.168.1.1")
    assert ip is not None
    assert str(ip) == "192.168.1.1"


async def test_normalize_ip_valid_ipv6():
    ip = normalize_ip("::1")
    assert ip is not None


async def test_normalize_ip_invalid():
    assert normalize_ip("not_an_ip") is None
    assert normalize_ip(None) is None
    assert normalize_ip("") is None


async def test_normalize_ip_bracketed_ipv6():
    ip = normalize_ip("[::1]")
    assert ip is not None
    assert str(ip) == "::1"


async def test_normalize_protocol():
    assert normalize_protocol("HTTPS") == "https"
    assert normalize_protocol(None) is None
    assert normalize_protocol("") is None


async def test_try_normalize_port():
    assert try_normalize_port(443) == 443
    assert try_normalize_port("80") == 80
    assert try_normalize_port(None) is None
    assert try_normalize_port("abc") is None
    assert try_normalize_port(0) is None
    assert try_normalize_port(70000) is None


async def test_split_endpoint_text_full_url():
    host, ip, port, protocol = split_endpoint_text("https://example.com:8443")
    assert host == "example.com"
    assert port == 8443
    assert protocol == "https"


async def test_split_endpoint_text_host_only():
    host, ip, port, protocol = split_endpoint_text("example.com")
    assert host == "example.com"


async def test_split_endpoint_text_ip():
    host, ip, port, protocol = split_endpoint_text("192.168.1.1")
    assert ip is not None
    assert str(ip) == "192.168.1.1"


async def test_split_endpoint_text_empty():
    host, ip, port, protocol = split_endpoint_text("")
    assert host is None
    assert ip is None


async def test_split_endpoint_text_ipv6():
    host, ip, port, protocol = split_endpoint_text("[::1]")
    assert ip is not None


async def test_split_endpoint_text_http_default_port():
    host, ip, port, protocol = split_endpoint_text("http://example.com")
    assert port == 80
    assert protocol == "http"


async def test_split_endpoint_text_https_default_port():
    host, ip, port, protocol = split_endpoint_text("https://api.example.com")
    assert port == 443
    assert protocol == "https"


# ---------------------------------------------------------------------------
# parse_host_rule / parse_host_rules
# ---------------------------------------------------------------------------

async def test_parse_host_rule_plain():
    rule = parse_host_rule("example.com")
    assert rule is not None
    assert rule.host == "example.com"
    assert rule.wildcard is False


async def test_parse_host_rule_wildcard():
    rule = parse_host_rule("*.example.com")
    assert rule is not None
    assert rule.host == "example.com"
    assert rule.wildcard is True


async def test_parse_host_rule_with_port():
    rule = parse_host_rule("example.com:8080")
    assert rule is not None
    assert rule.port == 8080


async def test_parse_host_rule_with_scheme():
    rule = parse_host_rule("https://example.com")
    assert rule is not None
    assert rule.protocol == "https"
    assert rule.host == "example.com"


async def test_parse_host_rule_scheme_and_port():
    rule = parse_host_rule("https://example.com:9443")
    assert rule is not None
    assert rule.protocol == "https"
    assert rule.port == 9443


async def test_parse_host_rule_empty_returns_none():
    assert parse_host_rule("") is None
    assert parse_host_rule("   ") is None


async def test_parse_host_rule_ip_address():
    rule = parse_host_rule("192.168.1.1")
    assert rule is not None
    assert rule.ip is not None
    assert rule.wildcard is False


async def test_parse_host_rules_multiple():
    rules = parse_host_rules(("example.com", "*.evil.com", ""))
    assert len(rules) == 2


# ---------------------------------------------------------------------------
# EgressPolicyEvaluator
# ---------------------------------------------------------------------------

async def test_egress_evaluator_no_rules_default_deny():
    """Default policy now uses deny egress action."""
    policy = PluginPolicy()
    evaluator = EgressPolicyEvaluator(policy)
    assert evaluator.is_configured is True
    decision = evaluator.evaluate(host="example.com")
    assert decision.allowed is False


async def test_egress_evaluator_default_deny():
    policy = PluginPolicy(default_egress_action="deny")
    evaluator = EgressPolicyEvaluator(policy)
    assert evaluator.is_configured is True
    decision = evaluator.evaluate(host="example.com")
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_EGRESS_HOST


async def test_egress_evaluator_default_deny_ip_only():
    policy = PluginPolicy(default_egress_action="deny")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(ip="10.0.0.1")
    assert decision.allowed is False
    # IP is normalized to host as well, so reason may be host or cidr
    assert decision.reason_code in (POLICY_REASON_DENIED_EGRESS_HOST, POLICY_REASON_DENIED_EGRESS_CIDR)


async def test_egress_evaluator_deny_host_exact():
    policy = PluginPolicy(egress_deny_hosts=["evil.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="evil.com")
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_EGRESS_HOST


async def test_egress_evaluator_deny_host_subdomain():
    policy = PluginPolicy(egress_deny_hosts=["evil.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="api.evil.com")
    assert decision.allowed is False


async def test_egress_evaluator_deny_host_no_match_allows():
    policy = PluginPolicy(egress_deny_hosts=["evil.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="good.com")
    assert decision.allowed is True


async def test_egress_evaluator_allow_hosts_explicit():
    policy = PluginPolicy(egress_allow_hosts=["api.example.com"])
    evaluator = EgressPolicyEvaluator(policy)
    # Allowed host
    d1 = evaluator.evaluate(host="api.example.com")
    assert d1.allowed is True
    # Not allowed host
    d2 = evaluator.evaluate(host="other.com")
    assert d2.allowed is False
    assert d2.reason_code == POLICY_REASON_DENIED_EGRESS_HOST


async def test_egress_evaluator_allow_hosts_subdomain_suffix():
    policy = PluginPolicy(egress_allow_hosts=["*.example.com"])
    evaluator = EgressPolicyEvaluator(policy)
    d1 = evaluator.evaluate(host="api.example.com")
    assert d1.allowed is True
    # Wildcard rule host='example.com'; exact match 'example.com' == 'example.com' is True in matching code
    d2 = evaluator.evaluate(host="example.com")
    assert d2.allowed is True
    # A completely different domain should be denied
    d3 = evaluator.evaluate(host="evil.com")
    assert d3.allowed is False


async def test_egress_evaluator_deny_port():
    policy = PluginPolicy(egress_deny_ports=[22], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com", port=22)
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_EGRESS_PORT


async def test_egress_evaluator_deny_port_allows_other():
    policy = PluginPolicy(egress_deny_ports=[22], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com", port=443)
    assert decision.allowed is True


async def test_egress_evaluator_allow_ports():
    policy = PluginPolicy(egress_allow_ports=[80, 443], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    d1 = evaluator.evaluate(host="example.com", port=443)
    assert d1.allowed is True
    d2 = evaluator.evaluate(host="example.com", port=8080)
    assert d2.allowed is False


async def test_egress_evaluator_allow_ports_none_port_denied():
    """If allow_ports is set and endpoint has no port, it's denied."""
    policy = PluginPolicy(egress_allow_ports=[443], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com")
    assert decision.allowed is False


async def test_egress_evaluator_deny_protocol():
    policy = PluginPolicy(egress_deny_protocols=["ftp"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com", protocol="ftp")
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_EGRESS_PROTOCOL


async def test_egress_evaluator_deny_protocol_allows_other():
    policy = PluginPolicy(egress_deny_protocols=["ftp"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com", protocol="https")
    assert decision.allowed is True


async def test_egress_evaluator_allow_protocols():
    policy = PluginPolicy(egress_allow_protocols=["https"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    d1 = evaluator.evaluate(host="example.com", protocol="https")
    assert d1.allowed is True
    d2 = evaluator.evaluate(host="example.com", protocol="http")
    assert d2.allowed is False


async def test_egress_evaluator_allow_protocols_none_denied():
    policy = PluginPolicy(egress_allow_protocols=["https"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com")
    assert decision.allowed is False


async def test_egress_evaluator_deny_cidr():
    policy = PluginPolicy(egress_deny_cidrs=["10.0.0.0/8"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(ip="10.1.2.3")
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_EGRESS_CIDR


async def test_egress_evaluator_deny_cidr_no_match():
    policy = PluginPolicy(egress_deny_cidrs=["10.0.0.0/8"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(ip="192.168.1.1")
    assert decision.allowed is True


async def test_egress_evaluator_allow_cidrs():
    policy = PluginPolicy(egress_allow_cidrs=["192.168.0.0/16"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    d1 = evaluator.evaluate(ip="192.168.1.1")
    assert d1.allowed is True
    d2 = evaluator.evaluate(ip="10.0.0.1")
    assert d2.allowed is False


async def test_egress_evaluator_deny_host_with_port():
    """Host rule with port should only deny matching port."""
    policy = PluginPolicy(egress_deny_hosts=["example.com:8080"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    d1 = evaluator.evaluate(host="example.com", port=8080)
    assert d1.allowed is False
    d2 = evaluator.evaluate(host="example.com", port=443)
    assert d2.allowed is True


async def test_egress_evaluator_deny_host_with_scheme():
    """Host rule with scheme should only deny matching protocol."""
    policy = PluginPolicy(egress_deny_hosts=["http://example.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    d1 = evaluator.evaluate(host="example.com", protocol="http")
    assert d1.allowed is False
    d2 = evaluator.evaluate(host="example.com", protocol="https")
    assert d2.allowed is True


async def test_egress_evaluator_endpoint_text():
    """evaluate() with endpoint_text should parse and evaluate."""
    policy = PluginPolicy(egress_deny_hosts=["evil.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(endpoint_text="https://evil.com:443/path")
    assert decision.allowed is False


async def test_egress_evaluator_normalize_endpoint():
    endpoint = EgressPolicyEvaluator.normalize_endpoint(
        endpoint_text="https://example.com:8443",
    )
    assert endpoint.host == "example.com"
    assert endpoint.port == 8443
    assert endpoint.protocol == "https"


async def test_egress_evaluator_normalize_endpoint_ip_inferred():
    endpoint = EgressPolicyEvaluator.normalize_endpoint(host="192.168.1.1")
    assert endpoint.ip is not None
    assert endpoint.host == "192.168.1.1"


async def test_egress_evaluator_normalize_endpoint_host_from_ip():
    endpoint = EgressPolicyEvaluator.normalize_endpoint(ip="10.0.0.1")
    assert endpoint.host == "10.0.0.1"
    assert endpoint.ip == "10.0.0.1"


async def test_egress_evaluator_normalize_endpoint_default_port():
    endpoint = EgressPolicyEvaluator.normalize_endpoint(host="example.com", protocol="https")
    assert endpoint.port == 443


async def test_egress_evaluator_pre_built_endpoint():
    """evaluate() with a pre-built EgressEndpoint."""
    policy = PluginPolicy(egress_deny_hosts=["evil.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    ep = EgressEndpoint(host="evil.com", ip=None, port=None, protocol=None)
    decision = evaluator.evaluate(endpoint=ep)
    assert decision.allowed is False


async def test_egress_decision_as_context():
    ep = EgressEndpoint(host="h", ip="1.2.3.4", port=80, protocol="http", source="probe")
    decision = EgressDecision(allowed=False, reason="r", reason_code="rc", policy_rule="pr", matcher="m", endpoint=ep)
    ctx = decision.as_context()
    assert ctx["host"] == "h"
    assert ctx["ip"] == "1.2.3.4"
    assert ctx["port"] == 80
    assert ctx["protocol"] == "http"
    assert ctx["policy_rule"] == "pr"
    assert ctx["egress_source"] == "probe"


async def test_egress_decision_as_context_no_endpoint():
    decision = EgressDecision(allowed=True)
    ctx = decision.as_context()
    assert ctx["host"] is None


# ---------------------------------------------------------------------------
# Egress: IPv6 CIDR matching
# ---------------------------------------------------------------------------

async def test_egress_evaluator_ipv6_deny_cidr():
    policy = PluginPolicy(egress_deny_cidrs=["fd00::/8"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(ip="fd00::1")
    assert decision.allowed is False


async def test_egress_evaluator_ipv6_allow():
    policy = PluginPolicy(egress_deny_cidrs=["fd00::/8"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(ip="2001:db8::1")
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Evaluation order: deny takes precedence
# ---------------------------------------------------------------------------

async def test_egress_deny_protocol_checked_before_host():
    """Deny protocol is checked before deny host rules."""
    policy = PluginPolicy(egress_deny_protocols=["ftp"], egress_deny_hosts=["example.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com", protocol="ftp")
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_EGRESS_PROTOCOL


async def test_egress_deny_port_checked_before_host():
    policy = PluginPolicy(egress_deny_ports=[22], egress_deny_hosts=["example.com"], default_egress_action="allow")
    evaluator = EgressPolicyEvaluator(policy)
    decision = evaluator.evaluate(host="example.com", port=22)
    assert decision.allowed is False
    assert decision.reason_code == POLICY_REASON_DENIED_EGRESS_PORT
