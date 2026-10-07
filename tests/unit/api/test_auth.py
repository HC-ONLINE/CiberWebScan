"""
Tests for API authentication module.

Tests for API Key authentication with security best practices.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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
from ciberwebscan.utils.logging import mask_identifier, mask_key_for_logging

pytestmark = pytest.mark.unit

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def test_api_key() -> str:
    """Test API key."""
    return "test-api-key-12345"


def _create_mock_config(
    api_keys: list[str] | None = None,
    server_secret: str = "test-server-secret-for-hmac",
) -> MagicMock:
    """Create a mock config object with api.auth settings."""
    mock_config = MagicMock()
    mock_config.api.auth.api_keys = api_keys or []
    mock_config.api.auth.server_secret = server_secret
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
# Default Server Secret Tests (api.auth.server_secret == "")
# =============================================================================


class TestDefaultServerSecret:
    """Tests for the auto-generated server secret with the default config."""

    @pytest.fixture(autouse=True)
    def reset_generated_secret(self, monkeypatch: pytest.MonkeyPatch):
        """Isolate the process-level secret cache for each test."""
        monkeypatch.setattr("ciberwebscan.utils.logging._generated_server_secret", None)

    def test_empty_secret_is_stable_across_calls(self):
        """Two consecutive calls must not generate a different secret each time."""
        mock_config = _create_mock_config(api_keys=["any-key"], server_secret="")
        with patch("ciberwebscan.api.auth.get_config", return_value=mock_config):
            first = get_auth_config().server_secret
            second = get_auth_config().server_secret

        assert first, "auto-generated server secret must not be empty"
        assert first == second

    def test_empty_secret_keeps_log_identifiers_correlatable(self):
        """mask_key_for_logging must return the same value across calls."""
        mock_config = _create_mock_config(api_keys=["any-key"], server_secret="")
        with patch("ciberwebscan.utils.logging.get_config", return_value=mock_config):
            first = mask_key_for_logging("abcd1234")
            second = mask_key_for_logging("abcd1234")

        assert first == second

    def test_configured_secret_is_never_replaced_by_cache(self):
        """An explicit secret always wins over a previously cached one."""
        empty_config = _create_mock_config(api_keys=[], server_secret="")
        explicit_config = _create_mock_config(
            api_keys=[], server_secret="explicit-secret"
        )

        with patch("ciberwebscan.api.auth.get_config", return_value=empty_config):
            auto_generated = get_auth_config().server_secret

        with patch("ciberwebscan.api.auth.get_config", return_value=explicit_config):
            assert get_auth_config().server_secret == "explicit-secret"

        with patch("ciberwebscan.api.auth.get_config", return_value=empty_config):
            assert get_auth_config().server_secret == auto_generated

    def test_concurrent_first_calls_agree_on_one_secret(self):
        """Concurrent first calls must generate the secret exactly once."""
        mock_config = _create_mock_config(api_keys=["any-key"], server_secret="")

        def _read_secret(_: int) -> str:
            return get_auth_config().server_secret

        with (
            patch("ciberwebscan.api.auth.get_config", return_value=mock_config),
            ThreadPoolExecutor(max_workers=8) as executor,
        ):
            secrets_seen = set(executor.map(_read_secret, range(32)))

        assert len(secrets_seen) == 1


# =============================================================================
# Log Identifier Masking Tests
# =============================================================================


class TestMaskIdentifier:
    """mask_identifier must keep raw API key material out of log messages."""

    @pytest.fixture(autouse=True)
    def reset_generated_secret(self, monkeypatch: pytest.MonkeyPatch):
        """Isolate the process-level secret cache for each test."""
        monkeypatch.setattr("ciberwebscan.utils.logging._generated_server_secret", None)

    def test_apikey_identifier_masks_the_key_id(self):
        """The 8-character key id must never appear verbatim in the result."""
        masked = mask_identifier("apikey:abcd1234")

        assert masked.startswith("apikey:")
        assert "abcd1234" not in masked
        assert len(masked) == len("apikey:") + 12

    def test_mask_is_stable_and_specific_to_the_key(self):
        """Same key → same log id; different key → different log id."""
        first = mask_identifier("apikey:abcd1234")
        second = mask_identifier("apikey:abcd1234")
        other_key = mask_identifier("apikey:abcd9999")

        assert first == second
        assert first != other_key

    def test_non_apikey_identifier_is_returned_unchanged(self):
        """Identifiers that carry no key material are left as they are."""
        assert mask_identifier("test_user") == "test_user"
        assert mask_identifier("") == ""


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
# Identifier Stability Tests (authorization identity)
# =============================================================================


class TestIdentifierStability:
    """The authorization identity must be stable and secret-independent."""

    @pytest.fixture(autouse=True)
    def reset_generated_secret(self, monkeypatch: pytest.MonkeyPatch):
        """Isolate the process-level secret cache for each test."""
        monkeypatch.setattr("ciberwebscan.utils.logging._generated_server_secret", None)

    @pytest.mark.asyncio
    async def test_verify_api_key_twice_same_identifier_default_secret(
        self, test_api_key
    ):
        """Same key, default (empty) secret, two calls → same identifier."""
        mock_config = _create_mock_config(api_keys=[test_api_key], server_secret="")
        with patch("ciberwebscan.api.auth.get_config", return_value=mock_config):
            first = await verify_api_key(_create_mock_request(), test_api_key)
            second = await verify_api_key(_create_mock_request(), test_api_key)

        assert first is not None and second is not None
        assert first.identifier == second.identifier
        assert first.identifier == f"apikey:{test_api_key[:8]}"

    def test_me_endpoint_identifier_stable_with_default_secret(
        self, client: TestClient, test_api_key
    ):
        """GET /auth/me twice with the same key returns the same identifier."""
        mock_config = _create_mock_config(api_keys=[test_api_key], server_secret="")
        with patch("ciberwebscan.api.auth.get_config", return_value=mock_config):
            response_one = client.get("/auth/me", headers={"X-API-Key": test_api_key})
            response_two = client.get("/auth/me", headers={"X-API-Key": test_api_key})

        assert response_one.status_code == 200
        assert response_two.status_code == 200
        assert response_one.json()["identifier"] == response_two.json()["identifier"]

    def test_me_endpoint_identifier_with_empty_secret(self, client, test_api_key):
        """Identifier is derived from the key id, not from server_secret."""
        mock_config = _create_mock_config(api_keys=[test_api_key], server_secret="")
        with patch("ciberwebscan.api.auth.get_config", return_value=mock_config):
            response = client.get("/auth/me", headers={"X-API-Key": test_api_key})

        assert response.status_code == 200
        assert response.json()["identifier"] == f"apikey:{test_api_key[:8]}"

    def test_identifier_is_independent_of_server_secret(self, client, test_api_key):
        """A different server_secret must not change the identity of a key."""
        with patch(
            "ciberwebscan.api.auth.get_config",
            return_value=_create_mock_config(
                api_keys=[test_api_key], server_secret="secret-one"
            ),
        ):
            first = client.get("/auth/me", headers={"X-API-Key": test_api_key})

        with patch(
            "ciberwebscan.api.auth.get_config",
            return_value=_create_mock_config(
                api_keys=[test_api_key], server_secret="secret-two"
            ),
        ):
            second = client.get("/auth/me", headers={"X-API-Key": test_api_key})

        assert first.json()["identifier"] == second.json()["identifier"]
        assert first.json()["identifier"] == f"apikey:{test_api_key[:8]}"

    @pytest.mark.asyncio
    async def test_different_keys_get_different_identifiers(self):
        """Two different keys must not share an identity."""
        mock_config = _create_mock_config(
            api_keys=["key-one-123456789", "key-two-123456789"], server_secret=""
        )
        with patch("ciberwebscan.api.auth.get_config", return_value=mock_config):
            first = await verify_api_key(_create_mock_request(), "key-one-123456789")
            second = await verify_api_key(_create_mock_request(), "key-two-123456789")

        assert first is not None and second is not None
        assert first.identifier != second.identifier


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
        from ciberwebscan.api.routes import analyze, attack, quick, scrape

        app = FastAPI()
        app.include_router(auth_router, prefix="/auth")
        app.include_router(scrape.router, prefix="/api")
        app.include_router(analyze.router, prefix="/api")
        app.include_router(attack.router, prefix="/api")
        app.include_router(quick.router, prefix="/api/quick")
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

    def test_quick_scan_requires_auth(
        self, protected_client: TestClient, auth_config_patch
    ):
        """Test /api/quick/scan requires authentication."""
        response = protected_client.post(
            "/api/quick/scan",
            json={"url": "https://example.com", "preset": "low"},
        )

        assert response.status_code == 401

    def test_quick_scan_with_api_key(
        self, protected_client: TestClient, auth_config_patch, test_api_key
    ):
        """Test /api/quick/scan works with API key."""
        response = protected_client.post(
            "/api/quick/scan",
            json={"url": "https://example.com", "preset": "low"},
            headers={"X-API-Key": test_api_key},
        )

        # May return 500 if service fails, but auth should pass
        assert response.status_code != 401

    def test_attack_requires_auth(
        self, protected_client: TestClient, auth_config_patch
    ):
        """Test /api/attack requires authentication."""
        response = protected_client.post(
            "/api/attack",
            json={"url": "https://example.com", "xss": True, "user_consent": True},
        )

        assert response.status_code == 401

    def test_attack_with_api_key(
        self, protected_client: TestClient, auth_config_patch, test_api_key
    ):
        """Test /api/attack works with API key."""
        response = protected_client.post(
            "/api/attack",
            json={"url": "https://example.com", "xss": True, "user_consent": True},
            headers={"X-API-Key": test_api_key},
        )

        # May return 500 if service fails, but auth should pass
        assert response.status_code != 401


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
