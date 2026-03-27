"""
Unit tests for auth route endpoints.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app


@pytest.fixture
def client():
    """Create a test client with auth dependency overridden."""
    from ciberwebscan.api.auth import AuthenticatedUser, get_current_user

    app = create_app()

    def mock_get_current_user() -> AuthenticatedUser:
        return AuthenticatedUser(
            identifier="test-user",
            auth_method="api_key",
            scopes=["read", "write"],
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    yield TestClient(app)
    app.dependency_overrides.clear()


class TestAuthRouteEndpoints:
    """Tests for /api/auth routes."""

    def test_get_me_returns_current_user(self, client: TestClient):
        response = client.get("/api/auth/me")

        assert response.status_code == 200
        body = response.json()
        assert body["identifier"] == "test-user"
        assert body["auth_method"] == "api_key"
        assert body["authenticated"] is True

    def test_generate_key_without_admin_scope_returns_403(self, client: TestClient):
        response = client.post("/api/auth/generate-key")

        assert response.status_code == 403
        assert "Admin access required" in response.json()["detail"]

    def test_generate_key_with_admin_scope_returns_200(self):
        from ciberwebscan.api.auth import AuthenticatedUser, get_current_user

        app = create_app()

        def mock_admin_user() -> AuthenticatedUser:
            return AuthenticatedUser(
                identifier="admin-user",
                auth_method="api_key",
                scopes=["admin"],
            )

        app.dependency_overrides[get_current_user] = mock_admin_user

        with patch(
            "ciberwebscan.api.routes.auth.generate_api_key",
            return_value="fixed-generated-key",
        ):
            response = TestClient(app).post("/api/auth/generate-key")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        body = response.json()
        assert body["api_key"] == "fixed-generated-key"
        assert "Store this key securely" in body["message"]
