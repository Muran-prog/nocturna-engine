"""Policy and security controls for Plugin Platform v2."""

POLICY_REASON_INVALID = "policy_invalid"
POLICY_REASON_DENIED_SUBPROCESS = "policy_denied_subprocess"
POLICY_REASON_DENIED_NETWORK = "policy_denied_network"
POLICY_REASON_DENIED_FILESYSTEM = "policy_denied_filesystem"
POLICY_REASON_DENIED_EGRESS_HOST = "policy_denied_egress_host"
POLICY_REASON_DENIED_EGRESS_PORT = "policy_denied_egress_port"
POLICY_REASON_DENIED_EGRESS_PROTOCOL = "policy_denied_egress_protocol"
POLICY_REASON_DENIED_EGRESS_CIDR = "policy_denied_egress_cidr"

_EGRESS_REASON_MAP: dict[str, str] = {
    POLICY_REASON_DENIED_EGRESS_HOST: "policy_denied:egress_host",
    POLICY_REASON_DENIED_EGRESS_PORT: "policy_denied:egress_port",
    POLICY_REASON_DENIED_EGRESS_PROTOCOL: "policy_denied:egress_protocol",
    POLICY_REASON_DENIED_EGRESS_CIDR: "policy_denied:egress_cidr",
}
