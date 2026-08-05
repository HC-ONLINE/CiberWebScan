"""
Integration tests for analyze endpoint.

Covers: test_api.py analyze, test_api_analyze.py.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


class TestAnalyzeEndpoint:
    """Tests for POST /api/analyze."""

    def test_analyze_basic(self, api_client: httpx.Client):
        payload = {
            "url": "https://httpbin.org/",
            "ssl": True,
            "fingerprint": True,
            "analyze_headers": True,
            "cve": False,
        }
        response = api_client.post("/api/analyze", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data.get("data") is not None

    def test_analyze_all_options(self, api_client: httpx.Client):
        payload = {
            "url": "https://example.com",
            "ssl": True,
            "fingerprint": True,
            "analyze_headers": True,
            "cve": False,
            "ssl_verify": True,
            "deep_scan": True,
            "check_robots": True,
            "enrich_exploits": True,
        }
        response = api_client.post("/api/analyze", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

    def test_analyze_requires_url(self, api_client: httpx.Client):
        response = api_client.post("/api/analyze", json={})
        assert response.status_code == 422
