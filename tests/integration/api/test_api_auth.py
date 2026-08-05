"""
Integration tests for auth endpoints.

Covers: test_api_connection.py, test_api_key_flow.py, test_api_robustness.py (auth parts).
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


class TestAuthStatus:
    """Tests for GET /api/auth/status."""

    def test_auth_status_returns_200(self, api_client: httpx.Client):
        response = api_client.get("/api/auth/status")
        assert response.status_code == 200

        data = response.json()
        assert "api_keys_configured" in data
        assert isinstance(data["api_keys_configured"], int)


class TestAuthMe:
    """Tests for GET /api/auth/me."""

    def test_auth_me_with_valid_key(self, api_client: httpx.Client):
        from ciberwebscan.config.loader import get_config

        config = get_config()
        if not config.api.auth.api_keys:
            pytest.skip("No API keys configured")

        api_key = config.api.auth.api_keys[0]
        headers = {"X-API-Key": api_key}

        response = api_client.get("/api/auth/me", headers=headers)
        assert response.status_code == 200

        data = response.json()
        assert data["authenticated"] is True
        assert data["auth_method"] == "api_key"

    def test_auth_me_with_invalid_key(self, api_client: httpx.Client):
        headers = {"X-API-Key": "invalid-key-12345"}
        response = api_client.get("/api/auth/me", headers=headers)
        assert response.status_code == 401

    def test_auth_me_without_key(self, api_client: httpx.Client):
        response = api_client.get("/api/auth/me")
        assert response.status_code == 401


class TestGenerateKey:
    """Tests for POST /api/auth/generate-key."""

    def test_generate_key_with_valid_key(self, api_client: httpx.Client):
        from ciberwebscan.config.loader import get_config

        config = get_config()
        if not config.api.auth.api_keys:
            pytest.skip("No API keys configured")

        api_key = config.api.auth.api_keys[0]
        headers = {"X-API-Key": api_key}

        response = api_client.post("/api/auth/generate-key", headers=headers)
        assert response.status_code == 200

        data = response.json()
        assert "api_key" in data
        assert len(data["api_key"]) > 0
        assert "Store this key securely" in data["message"]

    def test_generate_key_without_auth_returns_401(self, api_client: httpx.Client):
        response = api_client.post("/api/auth/generate-key")
        assert response.status_code == 401
