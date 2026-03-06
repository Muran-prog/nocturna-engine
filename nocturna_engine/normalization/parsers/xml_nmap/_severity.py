"""Port-based severity heuristics for nmap findings."""

from __future__ import annotations

from nocturna_engine.models.finding import SeverityLevel

# Port-based severity heuristic: well-known risky services.
_HIGH_RISK_PORTS: frozenset[int] = frozenset({
    21, 23, 25, 53, 110, 135, 137, 138, 139, 445, 512, 513, 514,
    1433, 1434, 1521, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 9200,
    11211, 27017,
})

_MEDIUM_RISK_PORTS: frozenset[int] = frozenset({
    22, 80, 443, 8443, 8888, 9090,
})


def _port_severity(port_id: int, state: str) -> SeverityLevel:
    """Determine severity of an open port based on port number and state.

    Args:
        port_id: TCP/UDP port number.
        state: Port state from nmap (open, filtered, etc.).

    Returns:
        SeverityLevel: Heuristic severity for this port.
    """
    if state != "open":
        return SeverityLevel.INFO
    if port_id in _HIGH_RISK_PORTS:
        return SeverityLevel.HIGH
    if port_id in _MEDIUM_RISK_PORTS:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW
