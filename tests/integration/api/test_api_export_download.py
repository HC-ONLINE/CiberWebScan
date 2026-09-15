"""
Integration tests for export + download token flow.

Covers: test_export_tokens.py, download_results.py, test_e2e_deletion.py.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.services.download_service import DownloadService

pytestmark = pytest.mark.integration

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


class _TargetHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that returns basic HTML for any request."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Test Target</h1></body></html>")

    def do_POST(self) -> None:
        self.do_GET()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture(scope="module")
def target_server() -> str:
    """Start a minimal HTTP server as attack target."""
    server = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://{host}:{port}"
    server.shutdown()


@pytest.fixture
def in_process_client(tmp_path: Path):
    """Create an in-process TestClient with mocked download config and user.

    Yields (client, mock_download_config) tuple.
    """
    app = create_app()

    mock_user = AuthenticatedUser(
        identifier="test_user",
        auth_method="api_key",
        scopes=["full_access"],
    )

    async def _override_user() -> AuthenticatedUser:
        return mock_user

    app.dependency_overrides[get_current_user] = _override_user

    with patch("ciberwebscan.services.download_service.get_config") as mock_dl_cfg:
        mock_dl_cfg.return_value.export.output_dir = str(tmp_path)
        mock_dl_cfg.return_value.download.max_file_size_mb = 10
        mock_dl_cfg.return_value.download.retention_seconds = 3600
        mock_dl_cfg.return_value.download.require_same_user = True
        mock_dl_cfg.return_value.download.max_retries = 3
        mock_dl_cfg.return_value.download.stream_chunk_size = 1024 * 1024
        mock_dl_cfg.return_value.download.enabled = True
        with TestClient(app) as client:
            yield client, mock_dl_cfg


@pytest.mark.network
class TestExportWithDownloadToken:
    """Tests that export parameter generates download tokens."""

    def test_analyze_with_export_returns_token(
        self, api_client: httpx.Client, auth_headers: dict
    ):
        payload = {
            "url": "https://example.com",
            "ssl": True,
            "fingerprint": True,
            "analyze_headers": True,
            "cve": False,
            "export": "analyze_export.json",
            "export_format": "json",
        }
        response = api_client.post("/api/analyze", json=payload, headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data.get("download_token") is not None

    def test_scrape_with_export_returns_token(
        self, api_client: httpx.Client, auth_headers: dict
    ):
        payload = {
            "url": "https://httpbin.org/html",
            "dynamic": False,
            "timeout": 10,
            "export": "scrape_export.json",
            "export_format": "json",
        }
        response = api_client.post("/api/scrape", json=payload, headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data.get("download_token") is not None

    def test_attack_with_export_returns_token(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ):
        payload = {
            "url": f"{target_server}/xss?q=test",
            "xss": True,
            "sqli": False,
            "traversal": False,
            "enumeration": False,
            "intensity": "low",
            "max_payloads": 3,
            "user_consent": True,
            "export": "attack_export.json",
            "export_format": "json",
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data.get("download_token") is not None

    def test_attack_with_export_handles_disabled_attacks(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ):
        payload = {
            "url": f"{target_server}/xss?q=test",
            "xss": True,
            "user_consent": True,
            "export": "attack_disabled.json",
            "export_format": "json",
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code in [200, 400]


class TestDownloadEndpoint:
    """Tests for GET /api/download/{token}."""

    def test_download_with_valid_token(self, in_process_client: tuple, tmp_path: Path):
        client, mock_dl_cfg = in_process_client

        test_file = tmp_path / "download_data.json"
        test_file.write_text('{"test": "download_data"}')

        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token = result.data.token

        response = client.get(f"/api/download/{token}")
        assert response.status_code == 200
        assert len(response.content) > 0

    def test_download_with_invalid_token(self, in_process_client: tuple):
        client, _ = in_process_client

        response = client.get("/api/download/invalid-token-abc")
        assert response.status_code in [404, 400]

    def test_downloaded_file_has_valid_json(
        self, in_process_client: tuple, tmp_path: Path
    ):
        client, mock_dl_cfg = in_process_client

        test_file = tmp_path / "valid.json"
        test_file.write_text('{"result": "integration_test", "items": [1, 2, 3]}')

        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token = result.data.token

        response = client.get(f"/api/download/{token}")
        assert response.status_code == 200

        content = response.json()
        assert "result" in content
        assert content["result"] == "integration_test"
        assert isinstance(content["items"], list)
        assert len(content["items"]) == 3

    def test_downloaded_csv_has_valid_content(
        self, in_process_client: tuple, tmp_path: Path
    ):
        client, mock_dl_cfg = in_process_client

        test_file = tmp_path / "data.csv"
        test_file.write_text("name,value\ntest_a,100\ntest_b,200\n")

        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="csv",
        )
        token = result.data.token

        response = client.get(f"/api/download/{token}")
        assert response.status_code == 200

        text = response.text
        lines = text.strip().splitlines()
        assert len(lines) == 3
        assert lines[0] == "name,value"
        assert "test_a" in lines[1]
        assert "test_b" in lines[2]

    def test_downloaded_html_has_valid_content(
        self, in_process_client: tuple, tmp_path: Path
    ):
        client, mock_dl_cfg = in_process_client

        test_file = tmp_path / "report.html"
        test_file.write_text("<html><body><h1>Report</h1><p>Data</p></body></html>")

        service = DownloadService()
        result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="html",
        )
        token = result.data.token

        response = client.get(f"/api/download/{token}")
        assert response.status_code == 200

        text = response.text
        assert "<html>" in text
        assert "<h1>Report</h1>" in text


class TestTokenLifecycle:
    """End-to-end token lifecycle test."""

    def test_token_generate_validate_delete(self, tmp_path: Path):
        test_file = tmp_path / "lifecycle.json"
        test_file.write_text('{"test": "lifecycle"}')

        with patch("ciberwebscan.services.download_service.get_config") as mock_cfg:
            mock_cfg.return_value.export.output_dir = str(tmp_path)
            mock_cfg.return_value.download.max_file_size_mb = 10
            mock_cfg.return_value.download.retention_seconds = 3600
            service = DownloadService()

            generate_result = service.generate_download_token(
                file_path=test_file,
                user_id="test_user",
                file_format="json",
            )
            assert generate_result.success
            token = generate_result.data.token

            validate_result = service.validate_download_request(
                token=token, user_id="test_user"
            )
            assert validate_result.success

            delete_result = service.delete_token(token)
            assert delete_result.success

            validate_after = service.validate_download_request(
                token=token, user_id="test_user"
            )
            assert not validate_after.success
