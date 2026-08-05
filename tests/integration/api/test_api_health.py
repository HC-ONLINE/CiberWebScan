"""
Integration tests for health endpoints.

Covers: test_api.py health + health/ready endpoints.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


class TestHealthEndpoints:
    """Tests for GET /health and GET /health/ready."""

    def test_health_returns_200(self, api_client: httpx.Client):
        response = api_client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_health_ready_returns_200(self, api_client: httpx.Client):
        response = api_client.get("/health/ready")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "ready"
