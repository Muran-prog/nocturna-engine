"""Shared pytest fixtures for engine tests."""

from __future__ import annotations

import pytest

from nocturna_engine.models.scan_request import ScanRequest
from nocturna_engine.models.target import Target


@pytest.fixture()
def sample_target() -> Target:
    """Build one standard target for tests.

    Returns:
        Target: Valid target model.
    """

    return Target(domain="example.com", scope=["example.com"])


@pytest.fixture()
def sample_request(sample_target: Target) -> ScanRequest:
    """Build one standard scan request for tests.

    Args:
        sample_target: Reusable target fixture.

    Returns:
        ScanRequest: Valid request model.
    """

    return ScanRequest(
        targets=[sample_target],
        timeout_seconds=5.0,
        retries=1,
        concurrency_limit=4,
    )

