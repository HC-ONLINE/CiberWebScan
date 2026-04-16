"""
Integration tests for download endpoint.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.services.download_service import DownloadService

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def client() -> TestClient:
    """Create a test client for the API."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def test_file() -> Path:
    """Create a temporary test file for downloading."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        f.write('{"test": "data", "result": "sample"}')
        return Path(f.name)


# =============================================================================
# Tests
# =============================================================================


class TestDownloadEndpoint:
    """Integration tests for GET /api/download/{token} endpoint."""

    def test_download_endpoint_registered(self, client: TestClient):
        """Verify endpoint is registered (returns 401 for auth, not 404 for route)."""
        # The endpoint returns 401 if not authenticated, not 404 if route doesn't exist
        response = client.get("/api/download/test-token")
        # Should NOT be 404 (route not found) - should be 401 (auth required)
        assert response.status_code != 404, "Endpoint not registered"

    def test_download_requires_auth(self, client: TestClient, test_file: Path):
        """Endpoint requires authentication."""
        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token

        # Try without auth - should be rejected
        response = client.get(f"/api/download/{token}")
        assert response.status_code in [401, 403], f"Got {response.status_code}"

    def test_download_endpoint_with_api_key(self, client: TestClient, test_file: Path):
        """Endpoint can be called with API key auth."""
        from ciberwebscan.config.loader import get_config

        config = get_config()
        if not config.api.auth.api_keys:
            pytest.skip("No API keys configured")

        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token
        api_key = config.api.auth.api_keys[0]

        # Try with valid API key - should not be auth error
        response = client.get(f"/api/download/{token}", headers={"X-API-Key": api_key})
        # Should be 200 (success) or 400/404 (token error), not 401 (auth error)
        assert (
            response.status_code != 401
        ), f"Auth should work with valid API key, got {response.status_code}"
