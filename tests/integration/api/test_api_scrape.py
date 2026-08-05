"""
Integration tests for scrape endpoint.

Covers: test_api.py scrape, test_api_scrape.py.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


class TestScrapeEndpoint:
    """Tests for POST /api/scrape."""

    def test_scrape_returns_success(self, api_client: httpx.Client):
        payload = {
            "url": "https://httpbin.org/html",
            "dynamic": False,
            "timeout": 10.0,
            "selector": "body",
        }
        response = api_client.post("/api/scrape", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data.get("data") is not None

    def test_scrape_requires_url(self, api_client: httpx.Client):
        response = api_client.post("/api/scrape", json={})
        assert response.status_code == 422

    def test_scrape_with_api_key(self, api_client: httpx.Client):
        from ciberwebscan.config.loader import get_config

        config = get_config()
        if not config.api.auth.api_keys:
            pytest.skip("No API keys configured")

        api_key = config.api.auth.api_keys[0]
        headers = {"X-API-Key": api_key}
        payload = {"url": "https://httpbin.org/html", "dynamic": False}

        response = api_client.post("/api/scrape", json=payload, headers=headers)
        assert response.status_code == 200
        assert response.json()["success"] is True
