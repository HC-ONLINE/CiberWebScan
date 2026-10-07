"""
Integration tests for downloads authenticated with a real API key.

Regression coverage for BUG-003: these tests intentionally do NOT override
``get_current_user``. The identity that issues a download token (request #1)
must match the identity of the request that redeems it (request #2) when the
same API key is used with the default configuration.
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.config.loader import get_config, reset_config
from ciberwebscan.services.download_service import DownloadService

pytestmark = pytest.mark.integration

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

TEST_API_KEY = "aaaa-bug003-download-key-alpha"
OTHER_API_KEY = "bbbb-bug003-download-key-beta"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Default configuration with an isolated HOME and test API keys."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv(
        "CIBERWEBSCAN_API_AUTH_API_KEYS", f"{TEST_API_KEY},{OTHER_API_KEY}"
    )
    monkeypatch.delenv("CIBERWEBSCAN_API_AUTH_SERVER_SECRET", raising=False)
    reset_config()
    return home


@pytest.fixture
def client(isolated_home: Path) -> TestClient:
    """In-process API client using the real auth dependencies (no overrides)."""
    return TestClient(create_app())


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Headers carrying the primary test API key."""
    return {"X-API-Key": TEST_API_KEY}


class _TargetHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that returns basic HTML for any request."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Bug003 Target</h1></body></html>")

    def do_POST(self) -> None:
        self.do_GET()

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def target_server() -> str:
    """Start a minimal loopback HTTP server as scan target."""
    server = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://{host}:{port}"
    server.shutdown()


# =============================================================================
# Helpers
# =============================================================================


def _identifier_of(client: TestClient, headers: dict[str, str]) -> str:
    """Resolve the authorization identity of an API key through the real path."""
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["identifier"]


def _write_export(home: Path, name: str, content: str) -> Path:
    """Create an export file inside the default export directory."""
    export_dir = home / ".ciberwebscan" / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    export_path = export_dir / name
    export_path.write_text(content, encoding="utf-8")
    return export_path


def _issue_token(user_id: str, export_path: Path) -> str:
    """Issue a download token the same way the POST routes do."""
    result = DownloadService().generate_download_token(
        file_path=export_path,
        user_id=user_id,
        file_format="json",
    )
    assert result.success, result.error
    assert result.data is not None
    return result.data.token


# =============================================================================
# Identity stability
# =============================================================================


class TestIdentityWithRealAuth:
    """The identity of an API key must be stable across requests."""

    def test_same_key_returns_same_identifier(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        first = _identifier_of(client, auth_headers)
        second = _identifier_of(client, auth_headers)

        assert first == second
        assert first == f"apikey:{TEST_API_KEY[:8]}"

    def test_other_key_returns_different_identifier(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        first = _identifier_of(client, auth_headers)
        other = _identifier_of(client, {"X-API-Key": OTHER_API_KEY})

        assert first != other


# =============================================================================
# Download with real auth
# =============================================================================


class TestDownloadWithRealAuth:
    """GET /api/download/{token} with real API key auth and default config."""

    def test_defaults_keep_access_control_enabled(self, isolated_home: Path):
        """require_same_user must stay enabled: no access control downgrade."""
        assert get_config().download.require_same_user is True
        assert get_config().api.auth.server_secret == ""

    def test_same_key_downloads_its_own_token(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        isolated_home: Path,
    ):
        identifier = _identifier_of(client, auth_headers)
        export_path = _write_export(isolated_home, "bug003_export.json", '{"ok": true}')
        token = _issue_token(identifier, export_path)

        response = client.get(f"/api/download/{token}", headers=auth_headers)

        assert response.status_code == 200, response.text
        assert b'"ok": true' in response.content

    def test_other_key_cannot_download_the_token(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        isolated_home: Path,
    ):
        identifier = _identifier_of(client, auth_headers)
        export_path = _write_export(
            isolated_home, "bug003_export_other.json", '{"ok": true}'
        )
        token = _issue_token(identifier, export_path)

        response = client.get(
            f"/api/download/{token}", headers={"X-API-Key": OTHER_API_KEY}
        )

        assert response.status_code == 401
        assert "different user" in response.json()["detail"]

    def test_missing_key_cannot_download_the_token(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        isolated_home: Path,
    ):
        identifier = _identifier_of(client, auth_headers)
        export_path = _write_export(
            isolated_home, "bug003_export_nokey.json", '{"ok": true}'
        )
        token = _issue_token(identifier, export_path)

        response = client.get(f"/api/download/{token}")

        assert response.status_code == 401


# =============================================================================
# Log hygiene: download events must never leak raw key material
# =============================================================================


class TestDownloadLogsAreMasked:
    """BUG-003 follow-up: log records carry the masked identity only."""

    @pytest.fixture(autouse=True)
    def reset_generated_secret(self, monkeypatch: pytest.MonkeyPatch):
        """Isolate the process-level secret cache for each test."""
        monkeypatch.setattr("ciberwebscan.utils.logging._generated_server_secret", None)

    def test_download_flow_logs_never_contain_the_raw_key_id(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        isolated_home: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        identifier = _identifier_of(client, auth_headers)
        export_path = _write_export(
            isolated_home, "bug003_export_log_ok.json", '{"ok": true}'
        )
        token = _issue_token(identifier, export_path)
        key_id = TEST_API_KEY[:8]

        with caplog.at_level(logging.INFO):
            accepted = client.get(f"/api/download/{token}", headers=auth_headers)

            other_path = _write_export(
                isolated_home, "bug003_export_log_denied.json", '{"ok": true}'
            )
            other_token = _issue_token(identifier, other_path)
            rejected = client.get(
                f"/api/download/{other_token}", headers={"X-API-Key": OTHER_API_KEY}
            )

        assert accepted.status_code == 200, accepted.text
        assert rejected.status_code == 401, rejected.text

        # Raw key material (the first 8 characters of the key) must not appear.
        assert key_id not in caplog.text
        assert f"apikey:{key_id}" not in caplog.text

        # Both the issuance and the denial are logged with the masked identity.
        assert "for user apikey:" in caplog.text
        assert "token owner apikey:" in caplog.text


# =============================================================================
# Full POST export -> download flow
# =============================================================================


@pytest.mark.network
class TestExportFlowWithRealAuth:
    """POST with export -> download_token -> GET download, no auth overrides."""

    @pytest.fixture(autouse=True)
    def allow_local_attacks(self, isolated_home: Path, monkeypatch: pytest.MonkeyPatch):
        """Enable the attack module against the loopback target."""
        monkeypatch.setenv("CIBERWEBSCAN_ATTACK_ENABLED", "true")
        monkeypatch.setenv("CIBERWEBSCAN_ATTACK_ALLOW_LOCAL", "true")
        reset_config()

    def test_export_token_is_downloadable_by_the_same_key(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        target_server: str,
    ):
        identifier_before = _identifier_of(client, auth_headers)

        payload = {
            "url": f"{target_server}/xss?q=test",
            "xss": True,
            "sqli": False,
            "traversal": False,
            "enumeration": False,
            "intensity": "low",
            "max_payloads": 3,
            "user_consent": True,
            "export": "bug003_attack.json",
            "export_format": "json",
        }
        response = client.post("/api/attack", json=payload, headers=auth_headers)
        assert response.status_code == 200, response.text

        body = response.json()
        assert body["success"] is True
        token = body.get("download_token")
        assert token, "POST with export must return a download token"

        identifier_after = _identifier_of(client, auth_headers)
        assert identifier_before == identifier_after

        # A different key must still be rejected before the owner downloads.
        rejected = client.get(
            f"/api/download/{token}", headers={"X-API-Key": OTHER_API_KEY}
        )
        assert rejected.status_code == 401

        download = client.get(f"/api/download/{token}", headers=auth_headers)
        assert download.status_code == 200, download.text
        assert len(download.content) > 0
