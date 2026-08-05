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

    def test_scrape_returns_success(self, api_client: httpx.Client, auth_headers: dict):
        payload = {
            "url": "https://httpbin.org/html",
            "dynamic": False,
            "timeout": 10.0,
            "selector": "body",
        }
        response = api_client.post("/api/scrape", json=payload, headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data.get("data") is not None

    def test_scrape_requires_url(self, api_client: httpx.Client, auth_headers: dict):
        response = api_client.post("/api/scrape", json={}, headers=auth_headers)
        assert response.status_code == 422
