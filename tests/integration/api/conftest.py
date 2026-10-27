"""
Shared fixtures for API integration tests.

Starts a real CiberWebScan API server for end-to-end testing.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx
import pytest

from ciberwebscan.config.loader import reset_config

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("python_multipart")

# Test-relevant environment for this suite, applied by the module-scoped
# integration_env fixture below instead of at import time: pytest
# collects the whole tree even when integration tests are deselected
# (CI runs -m "not integration"), so import-time pins would leak into
# unit tests sharing the process — e.g. scraping allow_local would make
# the SSRF unit tests attempt real connections instead of validating.
_INTEGRATION_ENV: dict[str, str] = {
    "CIBERWEBSCAN_API_AUTH_API_KEYS": "test-api-key-cwscan-integration",
    "CIBERWEBSCAN_ATTACK_ENABLED": "true",
    "CIBERWEBSCAN_ATTACK_ALLOW_LOCAL": "true",
    # Quick/analysis/scrape integration tests scan a controlled loopback
    # target (test_api_quick.py): opt local targets in per module so the
    # SSRF policy still applies everywhere else.
    "CIBERWEBSCAN_ANALYSIS_ALLOW_LOCAL": "true",
    "CIBERWEBSCAN_SCRAPING_ALLOW_LOCAL": "true",
    # Rate limiting is behaviour under test (test_api_robustness.py):
    # pin it enabled so a local ~/.ciberwebscan/config.yaml cannot
    # silently remove the middleware. The limit VALUE is left to the
    # effective test configuration and read dynamically by the test.
    "CIBERWEBSCAN_API_RATE_LIMIT_ENABLED": "true",
}

API_SERVER_PORT = 5556
API_SERVER_URL = f"http://127.0.0.1:{API_SERVER_PORT}"


@pytest.fixture(scope="module", autouse=True)
def integration_env():
    """Pin test-relevant environment variables for one integration module.

    Restores the previous values and reloads the config on teardown so
    the pins cannot bleed into other suites running in the same pytest
    process.
    """
    saved = {key: os.environ.get(key) for key in _INTEGRATION_ENV}
    for key, value in _INTEGRATION_ENV.items():
        os.environ.setdefault(key, value)
    reset_config()
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    reset_config()


@pytest.fixture(scope="module")
def api_server(integration_env):
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
def auth_headers(integration_env) -> dict[str, str]:
    """Get auth headers using the first configured API key."""
    from ciberwebscan.config.loader import get_config

    config = get_config()
    if not config.api.auth.api_keys:
        pytest.skip("No API keys configured")
    return {"X-API-Key": config.api.auth.api_keys[0]}
