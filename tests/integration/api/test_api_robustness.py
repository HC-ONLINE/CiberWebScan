"""
Integration tests for API robustness.

Covers: test_api_robustness.py (corrupt JSON handling).
Rate limiting tests are in tests/unit/api/test_middleware.py.
"""

from __future__ import annotations

import httpx
import pytest

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
