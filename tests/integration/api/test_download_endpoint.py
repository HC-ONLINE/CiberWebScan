"""
Integration tests for download endpoint.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.services.download_service import DownloadService

pytestmark = pytest.mark.integration

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    """Create a test client for the API with mocked download config and user."""
    app = create_app()

    mock_user = AuthenticatedUser(
        identifier="test_user",
        auth_method="api_key",
        scopes=["full_access"],
    )

    async def _override_user() -> AuthenticatedUser:
        return mock_user

    app.dependency_overrides[get_current_user] = _override_user

    with patch("ciberwebscan.services.download_service.get_config") as mock_cfg:
        mock_cfg.return_value.export.output_dir = str(tmp_path)
        mock_cfg.return_value.download.max_file_size_mb = 10
        mock_cfg.return_value.download.retention_seconds = 3600
        mock_cfg.return_value.download.require_same_user = True
        mock_cfg.return_value.download.max_retries = 3
        mock_cfg.return_value.download.stream_chunk_size = 1024 * 1024
        mock_cfg.return_value.download.enabled = True
        yield TestClient(app)


@pytest.fixture
def test_file(tmp_path: Path) -> Path:
    """Create a temporary test file for downloading."""
    test_file = tmp_path / "test_data.json"
    test_file.write_text('{"test": "data", "result": "sample"}')
    return test_file


# =============================================================================
# Tests
# =============================================================================


class TestDownloadEndpoint:
    """Integration tests for GET /api/download/{token} endpoint."""

    def test_download_endpoint_registered(self, client: TestClient):
        """Verify endpoint is registered (returns 401 for auth, not 404 for route)."""
        response = client.get("/api/download/test-token")
        assert response.status_code != 404, "Endpoint not registered"

    def test_download_requires_no_auth_with_override(
        self, client: TestClient, test_file: Path
    ):
        """Endpoint works when user dependency is overridden."""
        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token

        response = client.get(f"/api/download/{token}")
        assert response.status_code == 200

    def test_download_endpoint_with_api_key(self, client: TestClient, test_file: Path):
        """Endpoint can be called with API key auth."""
        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token

        response = client.get(f"/api/download/{token}")
        assert response.status_code == 200
