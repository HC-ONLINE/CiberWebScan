"""
Tests for API authentication module.

Tests for API Key authentication with security best practices.
"""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from ciberwebscan.api.auth import (
    _secure_compare_key,
    generate_api_key,
    get_auth_config,
    verify_api_key,
)
from ciberwebscan.api.routes.auth import router as auth_router

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def test_api_key() -> str:
    """Test API key."""
    return "test-api-key-12345"


def _create_mock_config(api_keys: list[str] | None = None) -> MagicMock:
    """Create a mock config object with api.auth settings."""
    mock_config = MagicMock()
    mock_config.api.auth.api_keys = api_keys or []
    return mock_config


def _create_mock_request(client_ip: str = "127.0.0.1") -> Mock:
    """Create a mock request object."""
    mock_request = Mock(spec=Request)
    mock_request.headers = {}
    mock_request.client = Mock()
    mock_request.client.host = client_ip
    mock_request.method = "GET"
    mock_request.url = Mock()
    mock_request.url.path = "/test"
    return mock_request


@pytest.fixture
def auth_config_patch(test_api_key: str):
    """Patch get_config to return test auth configuration."""
    mock_config = _create_mock_config(api_keys=[test_api_key])
    with patch("ciberwebscan.api.auth.get_config", return_value=mock_config):
        yield


@pytest.fixture
def app() -> FastAPI:
    """Create a FastAPI app with auth routes."""
    app = FastAPI()
    app.include_router(auth_router, prefix="/auth")
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create test client."""
    return TestClient(app)


# =============================================================================
# AuthConfig Tests
# =============================================================================


class TestAuthConfig:
    """Tests for AuthConfig loading."""

    def test_get_auth_config_with_config(self, auth_config_patch, test_api_key):
        """Test config loading from global config."""
        config = get_auth_config()

        assert config.api_key_enabled is True
        assert test_api_key in config.api_keys

    def test_get_auth_config_no_keys(self):
        """Test config with no keys configured."""
        mock_config = _create_mock_config(api_keys=[])
        with patch("ciberwebscan.api.auth.get_config", return_value=mock_config):
            config = get_auth_config()
            assert config.api_key_enabled is False
            assert config.api_keys == []


# =============================================================================
# Secure Key Comparison Tests
# =============================================================================


class TestSecureKeyComparison:
    """Tests for constant-time key comparison."""

    def test_secure_compare_valid_key(self):
        """Test constant-time comparison finds valid key."""
        stored_keys = ["key1-abcdef", "key2-ghijkl", "key3-mnopqr"]
        result = _secure_compare_key("key2-ghijkl", stored_keys)

        assert result == "key2-ghi"  # Returns first 8 chars

    def test_secure_compare_invalid_key(self):
        """Test constant-time comparison rejects invalid key."""
        stored_keys = ["key1-abcdef", "key2-ghijkl"]
        result = _secure_compare_key("invalid-key", stored_keys)

        assert result is None

    def test_secure_compare_empty_list(self):
        """Test comparison with empty key list."""
        result = _secure_compare_key("any-key", [])

        assert result is None

    def test_secure_compare_similar_keys(self):
        """Test comparison correctly distinguishes similar keys."""
        stored_keys = ["test-key-1"]

        # Should not match similar but different key
        assert _secure_compare_key("test-key-2", stored_keys) is None
        # Should match exact key
        assert _secure_compare_key("test-key-1", stored_keys) == "test-key"


# =============================================================================
# API Key Tests
# =============================================================================


class TestApiKeyAuthentication:
    """Tests for API key authentication."""

    @pytest.mark.asyncio
    async def test_verify_valid_api_key(self, auth_config_patch, test_api_key):
        """Test valid API key verification."""
        mock_request = _create_mock_request()
        user = await verify_api_key(mock_request, test_api_key)

        assert user is not None
        assert user.auth_method == "api_key"
        assert "full_access" in user.scopes

    @pytest.mark.asyncio
    async def test_verify_invalid_api_key(self, auth_config_patch):
        """Test invalid API key returns None."""
        mock_request = _create_mock_request()
        user = await verify_api_key(mock_request, "invalid-key")

        assert user is None

    @pytest.mark.asyncio
    async def test_verify_no_api_key(self, auth_config_patch):
        """Test no API key returns None."""
        mock_request = _create_mock_request()
        user = await verify_api_key(mock_request, None)

        assert user is None

    @pytest.mark.asyncio
    async def test_verify_logs_failed_attempt(self, auth_config_patch):
        """Test that failed authentication attempts are logged."""
        mock_request = _create_mock_request(client_ip="192.168.1.100")

        with patch("ciberwebscan.api.auth.logger") as mock_logger:
            await verify_api_key(mock_request, "bad-key-attempt")

            # Should log warning for failed attempt
            mock_logger.warning.assert_called()
            call_args = mock_logger.warning.call_args
            assert "Invalid API key attempt" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_verify_logs_success(self, auth_config_patch, test_api_key):
        """Test that successful authentication is logged."""
        mock_request = _create_mock_request()

        with patch("ciberwebscan.api.auth.logger") as mock_logger:
            await verify_api_key(mock_request, test_api_key)

            # Should log info for success
            mock_logger.info.assert_called()


# =============================================================================
# Auth Endpoint Tests
# =============================================================================


class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    def test_me_endpoint_with_api_key(
        self, client: TestClient, auth_config_patch, test_api_key
    ):
        """Test /auth/me with API key authentication."""
        response = client.get(
            "/auth/me",
            headers={"X-API-Key": test_api_key},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["auth_method"] == "api_key"
        assert data["authenticated"] is True

    def test_me_endpoint_without_auth(self, client: TestClient, auth_config_patch):
        """Test /auth/me without authentication fails."""
        response = client.get("/auth/me")

        assert response.status_code == 401

    def test_status_endpoint_removed(self, client: TestClient, auth_config_patch):
        """Test /auth/status endpoint no longer exists."""
        response = client.get("/auth/status")

        assert response.status_code == 404


# =============================================================================
# Protected Route Tests
# =============================================================================


class TestProtectedRoutes:
    """Tests for route protection."""

    @pytest.fixture
    def protected_app(self) -> FastAPI:
        """Create app with protected routes."""
        from ciberwebscan.api.routes import analyze, scrape

        app = FastAPI()
        app.include_router(auth_router, prefix="/auth")
        app.include_router(scrape.router, prefix="/api")
        app.include_router(analyze.router, prefix="/api")
        return app

    @pytest.fixture
    def protected_client(self, protected_app: FastAPI) -> TestClient:
        """Create test client for protected routes."""
        return TestClient(protected_app)

    def test_scrape_requires_auth(
        self, protected_client: TestClient, auth_config_patch
    ):
        """Test /api/scrape requires authentication."""
        response = protected_client.post(
            "/api/scrape",
            json={"url": "https://example.com"},
        )

        assert response.status_code == 401

    def test_scrape_with_api_key(
        self, protected_client: TestClient, auth_config_patch, test_api_key
    ):
        """Test /api/scrape works with API key."""
        response = protected_client.post(
            "/api/scrape",
            json={"url": "https://example.com"},
            headers={"X-API-Key": test_api_key},
        )

        # May return 500 if service fails, but auth should pass
        assert response.status_code != 401

    def test_analyze_requires_auth(
        self, protected_client: TestClient, auth_config_patch
    ):
        """Test /api/analyze requires authentication."""
        response = protected_client.post(
            "/api/analyze",
            json={"url": "https://example.com"},
        )

        assert response.status_code == 401


# =============================================================================
# Utility Tests
# =============================================================================


class TestUtilities:
    """Tests for utility functions."""

    def test_generate_api_key(self):
        """Test API key generation."""
        key1 = generate_api_key()
        key2 = generate_api_key()

        assert isinstance(key1, str)
        assert len(key1) >= 32
        assert key1 != key2  # Should be unique

    def test_generate_api_key_endpoint(
        self, client: TestClient, auth_config_patch, test_api_key
    ):
        """Test API key generation endpoint."""
        response = client.post(
            "/auth/generate-key",
            headers={"X-API-Key": test_api_key},
        )

        assert response.status_code == 200
        data = response.json()
        assert "api_key" in data
        assert len(data["api_key"]) >= 32


# =============================================================================
# Security Tests
# =============================================================================


class TestSecurityMeasures:
    """Tests for security measures."""

    def test_auth_required_returns_401_not_403(
        self, client: TestClient, auth_config_patch
    ):
        """Test unauthenticated requests get 401, not 403."""
        response = client.get("/auth/me")

        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers

    def test_invalid_key_returns_401(self, client: TestClient, auth_config_patch):
        """Test invalid API key returns 401."""
        response = client.get(
            "/auth/me",
            headers={"X-API-Key": "definitely-not-a-valid-key"},
        )

        assert response.status_code == 401

    def test_generate_key_requires_auth(self, client: TestClient, auth_config_patch):
        """Test generate-key endpoint requires authentication."""
        response = client.post("/auth/generate-key")

        assert response.status_code == 401
