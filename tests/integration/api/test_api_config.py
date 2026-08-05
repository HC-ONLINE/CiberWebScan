"""
Integration tests for config endpoints.

Covers: test_config_api_demo.py.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


class TestConfigEndpoints:
    """Tests for configuration management endpoints."""

    def test_get_all_config(self, api_client: httpx.Client, auth_headers: dict):
        response = api_client.get("/api/config", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert isinstance(data.get("data"), dict)

    def test_get_config_section(self, api_client: httpx.Client, auth_headers: dict):
        response = api_client.get("/api/config/sections/scraping", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

    def test_get_config_value(self, api_client: httpx.Client, auth_headers: dict):
        response = api_client.get(
            "/api/config/value",
            params={"path": "scraping.timeout"},
            headers=auth_headers,
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert "value" in data.get("data", {})

    def test_update_config(self, api_client: httpx.Client, auth_headers: dict):
        payload = {"path": "scraping.timeout", "value": 60, "save": False}
        response = api_client.put("/api/config", json=payload, headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

    def test_list_config_keys(self, api_client: httpx.Client, auth_headers: dict):
        response = api_client.get("/api/config/keys", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert "count" in data.get("data", {})

    def test_reset_config(self, api_client: httpx.Client, auth_headers: dict):
        payload = {"path": "scraping.timeout", "save": False}
        response = api_client.post(
            "/api/config/reset", json=payload, headers=auth_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True


class TestOpenAPIDiscovery:
    """Tests for OpenAPI specification endpoint."""

    def test_openapi_speclists_config_endpoints(self, api_client: httpx.Client):
        response = api_client.get("/openapi.json")
        assert response.status_code == 200

        spec = response.json()
        paths = spec.get("paths", {})
        config_endpoints = [p for p in paths if "/config" in p]
        assert len(config_endpoints) >= 5, (
            f"Expected at least 5 config endpoints, found {len(config_endpoints)}"
        )
