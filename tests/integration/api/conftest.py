"""
Shared fixtures for API integration tests.

Starts a real CiberWebScan API server for end-to-end testing.
"""

from __future__ import annotations

import subprocess
import sys
import time

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("python_multipart")

API_SERVER_PORT = 5556
API_SERVER_URL = f"http://127.0.0.1:{API_SERVER_PORT}"


@pytest.fixture(scope="module")
def api_server():
    """Start CiberWebScan API server for integration tests."""
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "ciberwebscan.api.app:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(API_SERVER_PORT),
        "--log-level",
        "error",
    ]
    server_process = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    max_attempts = 30
    for _ in range(max_attempts):
        try:
            with httpx.Client() as client:
                response = client.get(f"{API_SERVER_URL}/health", timeout=1.0)
                if response.status_code == 200:
                    break
        except (httpx.RequestError, httpx.TimeoutException):
            time.sleep(0.1)
    else:
        server_process.terminate()
        server_process.wait()
        pytest.fail("API server failed to start")

    yield API_SERVER_URL

    try:
        server_process.terminate()
        server_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server_process.kill()
        server_process.wait()


@pytest.fixture(scope="module")
def api_client(api_server: str) -> httpx.Client:
    """Create an httpx client pointing at the test API server."""
    return httpx.Client(base_url=api_server, timeout=30.0)


@pytest.fixture(scope="module")
def auth_headers() -> dict[str, str]:
    """Get auth headers using the first configured API key."""
    from ciberwebscan.config.loader import get_config

    config = get_config()
    if not config.api.auth.api_keys:
        pytest.skip("No API keys configured")
    return {"X-API-Key": config.api.auth.api_keys[0]}
