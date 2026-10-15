"""
Integration tests for download endpoint.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.services.base import ServiceResult
from ciberwebscan.services.download_service import DownloadService, _registry

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

    # Patch get_config in BOTH the service (validation/streaming) and the
    # route module (download.enabled gate): an ambient
    # CIBERWEBSCAN_DOWNLOAD_ENABLED=false or a local config with
    # download.enabled=false would otherwise turn these tests into 503s.
    with (
        patch("ciberwebscan.services.download_service.get_config") as mock_svc_cfg,
        patch("ciberwebscan.api.routes.download.get_config") as mock_route_cfg,
    ):
        for mock_cfg in (mock_svc_cfg, mock_route_cfg):
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


class TestDownloadFailurePaths:
    """Server-side failures return the reserved attempt (policy α).

    The client fixture pins ``download.max_retries`` to 3, so a fresh token
    starts with 3 attempts: the request consumes one on validation and a
    server-side failure must give it back (ending at 3 again).

    These tests exercise SERVER failures only (before and during delivery)
    plus the successful path; the client-disconnect path is a distinct
    mechanism (``GeneratorExit``) and is covered deterministically at unit
    level in ``tests/unit/api/routes/test_download.py`` — it must not be
    simulated here with an unrelated exception.
    """

    def test_stream_failure_returns_attempt(self, client: TestClient, test_file: Path):
        """Scenario 1: get_file_stream fails -> 500, token kept, 3 -> 3."""
        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token

        with patch.object(
            DownloadService,
            "get_file_stream",
            return_value=ServiceResult.fail("storage unavailable"),
        ):
            response = client.get(f"/api/download/{token}")

        assert response.status_code == 500
        assert response.json()["detail"] == "Failed to retrieve file"
        info = asyncio.run(_registry.get_info(token))
        assert info is not None, "token must survive a server-side failure"
        assert info.attempts_remaining == 3, "the reserved attempt must be returned"

        # The token is genuinely reusable end-to-end once the fault clears.
        retry = client.get(f"/api/download/{token}")
        assert retry.status_code == 200
        assert retry.content == test_file.read_bytes()

    def test_missing_stream_data_returns_attempt(
        self, client: TestClient, test_file: Path
    ):
        """Scenario 2: stream result without data -> 500 and attempt returned."""
        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token

        with patch.object(
            DownloadService,
            "get_file_stream",
            return_value=ServiceResult(success=True, data=None),
        ):
            response = client.get(f"/api/download/{token}")

        assert response.status_code == 500
        assert response.json()["detail"] == "Failed to retrieve file stream"
        info = asyncio.run(_registry.get_info(token))
        assert info is not None
        assert info.attempts_remaining == 3

    def test_mid_stream_failure_refunds_and_keeps_token(
        self, client: TestClient, test_file: Path
    ):
        """Scenario 3 (endpoint): server error during delivery refunds once.

        ``get_file_stream`` yields one chunk and then raises: the error
        propagates through the ASGI stack (TestClient re-raises it) after
        ``_stream_and_cleanup`` refunds the reservation and keeps the token.
        """
        max_retries = 3
        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token

        def _broken_stream() -> Iterator[bytes]:
            yield b"first-chunk"
            raise OSError("simulated read error mid-stream")

        with (
            patch.object(
                DownloadService,
                "get_file_stream",
                return_value=ServiceResult(success=True, data=_broken_stream()),
            ),
            pytest.raises(OSError, match="mid-stream"),
        ):
            client.get(f"/api/download/{token}")

        info = asyncio.run(_registry.get_info(token))
        assert info is not None, "a mid-stream server failure keeps the token"
        assert info.attempts_remaining == max_retries, (
            "the reserved attempt must be returned"
        )

    def test_full_download_returns_content_and_deletes_token(
        self, client: TestClient, test_file: Path
    ):
        """Scenario 5 (endpoint): 200 with the exact content; token deleted."""
        expected = test_file.read_bytes()
        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )
        token = result.data.token

        response = client.get(f"/api/download/{token}")

        assert response.status_code == 200
        assert response.content == expected
        assert asyncio.run(_registry.get_info(token)) is None, (
            "a completed download must delete the token"
        )
