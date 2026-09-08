"""
Integration tests for export + download token flow.

Covers: test_export_tokens.py, download_results.py, test_e2e_deletion.py.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from ciberwebscan.services.download_service import DownloadService

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")


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
        self, api_client: httpx.Client, auth_headers: dict
    ):
        payload = {
            "url": "http://127.0.0.1:5555/",
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
        self, api_client: httpx.Client, auth_headers: dict
    ):
        payload = {
            "url": "http://127.0.0.1:5555/",
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

    def test_download_with_valid_token(
        self, api_client: httpx.Client, auth_headers: dict, tmp_path: Path
    ):
        from unittest.mock import patch

        test_file = tmp_path / "download_data.json"
        test_file.write_text('{"test": "download_data"}')

        with patch("ciberwebscan.services.download_service.get_config") as mock_cfg:
            mock_cfg.return_value.export.output_dir = str(tmp_path)
            mock_cfg.return_value.download.max_file_size_mb = 10
            mock_cfg.return_value.download.retention_seconds = 3600
            service = DownloadService()
            result = service.generate_download_token(
                file_path=test_file,
                user_id="test_user",
                file_format="json",
            )
            token = result.data.token

            response = api_client.get(f"/api/download/{token}", headers=auth_headers)
            assert response.status_code == 200
            assert len(response.content) > 0

    def test_download_with_invalid_token(
        self, api_client: httpx.Client, auth_headers: dict
    ):
        response = api_client.get(
            "/api/download/invalid-token-abc", headers=auth_headers
        )
        assert response.status_code in [404, 400]

    def test_downloaded_file_has_valid_json(
        self, api_client: httpx.Client, auth_headers: dict, tmp_path: Path
    ):
        from unittest.mock import patch

        test_file = tmp_path / "valid.json"
        test_file.write_text('{"result": "integration_test", "items": [1, 2, 3]}')

        with patch("ciberwebscan.services.download_service.get_config") as mock_cfg:
            mock_cfg.return_value.export.output_dir = str(tmp_path)
            mock_cfg.return_value.download.max_file_size_mb = 10
            mock_cfg.return_value.download.retention_seconds = 3600
            service = DownloadService()
            result = service.generate_download_token(
                file_path=test_file,
                user_id="test_user",
                file_format="json",
            )
            token = result.data.token

            response = api_client.get(f"/api/download/{token}", headers=auth_headers)
            assert response.status_code == 200

            content = response.json()
            assert "result" in content
            assert content["result"] == "integration_test"
            assert isinstance(content["items"], list)
            assert len(content["items"]) == 3

    def test_downloaded_csv_has_valid_content(
        self, api_client: httpx.Client, auth_headers: dict, tmp_path: Path
    ):
        from unittest.mock import patch

        test_file = tmp_path / "data.csv"
        test_file.write_text("name,value\ntest_a,100\ntest_b,200\n")

        with patch("ciberwebscan.services.download_service.get_config") as mock_cfg:
            mock_cfg.return_value.export.output_dir = str(tmp_path)
            mock_cfg.return_value.download.max_file_size_mb = 10
            mock_cfg.return_value.download.retention_seconds = 3600
            service = DownloadService()
            result = service.generate_download_token(
                file_path=test_file,
                user_id="test_user",
                file_format="csv",
            )
            token = result.data.token

            response = api_client.get(f"/api/download/{token}", headers=auth_headers)
            assert response.status_code == 200

            text = response.text
            lines = text.strip().split("\n")
            assert len(lines) == 3
            assert lines[0] == "name,value"
            assert "test_a" in lines[1]
            assert "test_b" in lines[2]

    def test_downloaded_html_has_valid_content(
        self, api_client: httpx.Client, auth_headers: dict, tmp_path: Path
    ):
        from unittest.mock import patch

        test_file = tmp_path / "report.html"
        test_file.write_text("<html><body><h1>Report</h1><p>Data</p></body></html>")

        with patch("ciberwebscan.services.download_service.get_config") as mock_cfg:
            mock_cfg.return_value.export.output_dir = str(tmp_path)
            mock_cfg.return_value.download.max_file_size_mb = 10
            mock_cfg.return_value.download.retention_seconds = 3600
            service = DownloadService()
            result = service.generate_download_token(
                file_path=test_file,
                user_id="test_user",
                file_format="html",
            )
            token = result.data.token

            response = api_client.get(f"/api/download/{token}", headers=auth_headers)
            assert response.status_code == 200

            text = response.text
            assert "<html>" in text
            assert "<h1>Report</h1>" in text


class TestTokenLifecycle:
    """End-to-end token lifecycle test."""

    def test_token_generate_validate_delete(self, tmp_path: Path):
        test_file = tmp_path / "lifecycle.json"
        test_file.write_text('{"test": "lifecycle"}')

        from unittest.mock import patch

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
