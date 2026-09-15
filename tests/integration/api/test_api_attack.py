"""
Integration tests for attack endpoint.

Covers: test_api.py attack, test_api_attack.py.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

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
        pass  # Suppress request logs during tests


@pytest.fixture(scope="module")
def target_server() -> str:
    """Start a minimal HTTP server as attack target.

    Returns the base URL (e.g. ``http://127.0.0.1:<port>``).
    """
    server = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://{host}:{port}"
    server.shutdown()


@pytest.mark.network
class TestAttackEndpoint:
    """Tests for POST /api/attack."""

    def test_attack_xss_only(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ):
        payload = {
            "url": f"{target_server}/xss?q=test",
            "xss": True,
            "sqli": False,
            "traversal": False,
            "enumeration": False,
            "intensity": "low",
            "max_payloads": 5,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

        attack_data = data.get("data")
        assert attack_data is not None
        assert attack_data["target_url"] == payload["url"]
        assert isinstance(attack_data["total_payloads_tested"], int)
        assert isinstance(attack_data["total_findings"], int)
        assert isinstance(attack_data["vulnerabilities"], list)

        for key in (
            "xss_findings",
            "sqli_findings",
            "traversal_findings",
            "enumeration_findings",
            "csrf_findings",
            "subdomain_findings",
        ):
            assert key in attack_data
            assert isinstance(attack_data[key], int)

    def test_attack_sqli_only(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ):
        payload = {
            "url": f"{target_server}/user?id=1",
            "xss": False,
            "sqli": True,
            "traversal": False,
            "enumeration": False,
            "intensity": "low",
            "max_payloads": 5,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

        attack_data = data.get("data")
        assert attack_data is not None
        assert attack_data["target_url"] == payload["url"]
        assert isinstance(attack_data["sqli_findings"], int)

    def test_attack_all_attacks(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ):
        payload = {
            "url": f"{target_server}/",
            "all_attacks": True,
            "intensity": "low",
            "max_payloads": 3,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["data"]["total_payloads_tested"] >= 0

    def test_attack_traversal_enumeration(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ):
        payload = {
            "url": f"{target_server}/",
            "xss": False,
            "sqli": False,
            "traversal": True,
            "enumeration": True,
            "intensity": "low",
            "max_payloads": 5,
            "user_consent": True,
        }
        response = api_client.post(
            "/api/attack", json=payload, headers=auth_headers, timeout=120
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

    def test_attack_missing_consent_returns_422(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ):
        payload = {
            "url": f"{target_server}/",
            "xss": True,
            "user_consent": False,
        }
        response = api_client.post("/api/attack", json=payload, headers=auth_headers)
        assert response.status_code == 422
