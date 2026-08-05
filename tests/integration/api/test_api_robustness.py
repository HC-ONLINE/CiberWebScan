"""
Integration tests for API robustness.

Covers: test_api_robustness.py (corrupt JSON + rate limiting).
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


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


class TestRateLimiting:
    """Tests for rate limiting middleware."""

    def test_rate_limit_enforced(self, api_server: str):
        success_count = 0
        limited_count = 0

        for _ in range(65):
            try:
                response = httpx.get(f"{api_server}/health", timeout=2)
                if response.status_code == 200:
                    success_count += 1
                elif response.status_code == 429:
                    limited_count += 1
                    break
            except httpx.RequestError:
                break

        assert limited_count > 0, (
            f"Rate limit not triggered after {success_count} requests"
        )
