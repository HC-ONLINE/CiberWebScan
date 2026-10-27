"""
Integration tests for the quick endpoint (POST /api/quick/scan).

Runs against the real Uvicorn server: routing, middleware, auth, request
validation, QuickService, AnalyzeService and ScrapeService execute for
real. The only stand-in is a controlled loopback target HTTP server
(reproducible, no external services) that counts the requests the scan
actually makes; there are no service-level mocks.

Note: with ``selector`` the scrape phase runs real requests but its
structured result is a list, which QuickService does not embed in
``report.scrape`` (selector mode); the round trip is therefore asserted
against the target's request counter.

Covers: quick endpoint coverage lost with the manual scripts (see
backup/stash-api-manual-52cc50e).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

pytestmark = pytest.mark.integration

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

_TARGET_HTML = (
    b"<html><head><title>Integration Target</title></head>"
    b"<body>quick-scan-target-marker</body></html>"
)


class _TargetHandler(BaseHTTPRequestHandler):
    """Minimal local target that serves fixed HTML and counts requests."""

    request_count = 0

    def do_GET(self) -> None:
        _TargetHandler.request_count += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_TARGET_HTML)))
        self.end_headers()
        self.wfile.write(_TARGET_HTML)

    def do_POST(self) -> None:
        self.do_GET()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # Suppress request logs during tests


@pytest.fixture(scope="module")
def target_server() -> str:
    """Start a controlled loopback HTTP server as scan target.

    Returns the base URL (e.g. ``http://127.0.0.1:<port>``).
    """
    server = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://{host}:{port}"
    server.shutdown()


@pytest.mark.network
class TestQuickScanEndpoint:
    """Functional tests for POST /api/quick/scan over real HTTP."""

    def test_quick_scan_low_runs_real_services(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ) -> None:
        """A low-preset scan really analyses the local target end to end."""
        payload = {
            "url": f"{target_server}/",
            "preset": "low",
            "selector": "body",
        }
        response = api_client.post(
            "/api/quick/scan", json=payload, headers=auth_headers, timeout=60
        )
        assert response.status_code == 200

        body = response.json()
        assert body["success"] is True
        assert body["preset"] == "low"
        assert isinstance(body["warnings"], list)
        assert body["duration_seconds"] > 0

        data = body["data"]
        assert data is not None

        # The report points at the target that was requested.
        assert data["meta"]["target_url"].rstrip("/") == target_server

        # Analysis really ran against the local target: an http:// URL
        # yields an SSL result without TLS, and fingerprint/headers
        # results come from real requests to the target above.
        assert data["ssl"] is not None
        assert data["ssl"]["is_https"] is False
        assert data["fingerprint"] is not None
        assert isinstance(data["headers"]["findings"], list)

        # Proof of a real network round trip: the scan reached the target
        # (consent/auth failures below never produce target requests).
        assert _TargetHandler.request_count >= 1

    def test_quick_scan_medium_requires_consent(
        self, api_client: httpx.Client, auth_headers: dict, target_server: str
    ) -> None:
        """Medium preset without consent fails fast with 400 CONSENT_REQUIRED."""
        payload = {"url": f"{target_server}/", "preset": "medium"}
        response = api_client.post(
            "/api/quick/scan", json=payload, headers=auth_headers
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert detail["error_code"] == "CONSENT_REQUIRED"

    def test_quick_scan_requires_api_key(
        self, api_client: httpx.Client, target_server: str
    ) -> None:
        """Requests without a key are rejected before any scan work."""
        payload = {"url": f"{target_server}/", "preset": "low"}
        response = api_client.post("/api/quick/scan", json=payload)
        assert response.status_code == 401
