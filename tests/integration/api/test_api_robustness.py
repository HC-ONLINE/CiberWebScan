"""
Integration tests for API robustness.

Covers: test_api_robustness.py (corrupt JSON handling, rate limit burst).
Rate limiting unit logic lives in tests/unit/api/test_middleware.py;
enforcement end-to-end over real HTTP is asserted here.
"""

from __future__ import annotations

import time

import httpx
import pytest

from ciberwebscan.config.loader import get_config

pytestmark = pytest.mark.integration

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


@pytest.mark.network
class TestCorruptInput:
    """Tests for malformed request handling."""

    def test_corrupt_json_returns_422(self, api_server: str):
        response = httpx.post(
            f"{api_server}/api/attack",
            content='{"scopes": ["full_access"',
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test",
            },
            timeout=10,
        )
        assert response.status_code == 422


@pytest.mark.network
class TestRateLimitingOverHttp:
    """End-to-end rate limiting through the real middleware.

    Runs against the module-scoped uvicorn server, so this file owns an
    isolated process and therefore an isolated in-memory rate-limit
    counter (all requests come from the peer ``127.0.0.1`` and share one
    bucket). The burst size is derived from the effective test
    configuration instead of assuming a fixed number of requests, and the
    assertions are guarded against the wall-clock minute boundary so the
    result does not depend on landing exactly on a window edge.
    """

    def test_burst_beyond_limit_gets_429_with_retry_after(
        self, api_server: str
    ) -> None:
        config = get_config()
        assert config.api.rate_limit.enabled, (
            "rate limiting must stay enabled in the integration environment"
        )
        limit = config.api.rate_limit.requests_per_minute

        # Worst case: the minute window rotates once mid-burst and the
        # whole limit has to be consumed again. Two full windows plus a
        # small margin bound the loop without hardcoding e.g. "70".
        max_requests = 2 * limit + 10
        allowed = 0
        first_allowed: httpx.Response | None = None
        limited: httpx.Response | None = None

        started = time.time()
        with httpx.Client(base_url=api_server, timeout=10.0) as client:
            for _ in range(max_requests):
                response = client.get("/health")
                if response.status_code == 429:
                    limited = response
                    break
                assert response.status_code == 200, (
                    "requests under the limit must honour the endpoint "
                    f"contract, got {response.status_code}"
                )
                if first_allowed is None:
                    first_allowed = response
                allowed += 1
            ended = time.time()

            assert limited is not None, (
                f"no 429 after {allowed} requests although the configured "
                f"limit is {limit}: rate limiting is not being enforced"
            )

            # Observable contract of the limited response.
            assert "Retry-After" in limited.headers, (
                "429 responses must advertise Retry-After"
            )
            retry_after_raw = limited.headers["Retry-After"]
            assert retry_after_raw.isdigit(), (
                f"Retry-After must be an integer number of seconds, "
                f"got {retry_after_raw!r}"
            )
            retry_after = int(retry_after_raw)
            assert 1 <= retry_after <= 60

            # Rejected requests do not reset the counter: still limited in
            # the same window. Guarded against the rare case where the
            # window boundary arrives within the next couple of seconds.
            if retry_after > 2:
                again = client.get("/health")
                assert again.status_code == 429, (
                    "a rejected client must stay limited until the window ends"
                )
                assert "Retry-After" in again.headers

        # Allowed requests answered according to the /health contract.
        assert first_allowed is not None and allowed >= 1, (
            "expected at least one request to be served before the limit; "
            "an earlier test may have exhausted this window's budget"
        )
        health = first_allowed.json()
        assert health["status"] == "healthy"
        assert isinstance(health["version"], str)

        # Within a single window the middleware must not admit more than
        # the configured limit. If the wall-clock minute rotated mid-test
        # the counter legitimately reset, so the bound only holds when the
        # burst stayed inside one window.
        if int(started // 60) == int(ended // 60):
            assert allowed <= limit, (
                f"admitted {allowed} requests although the limit is {limit}"
            )

        body = limited.json()
        assert isinstance(body.get("error"), str)
        assert body.get("retry_after_seconds") == retry_after
