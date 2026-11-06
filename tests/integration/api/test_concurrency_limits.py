"""
Integration tests for scan admission control under real concurrency (BUG-013).

Unlike the older concurrency tests (which prove the event loop is not
blocked), these exercise the admission limit itself against a real uvicorn
server on 127.0.0.1 with a controlled blocking backend:

- The excess beyond ``api.max_concurrent_scans`` is rejected with 429
  immediately (no unbounded queue).
- /health stays responsive while every scan slot is occupied.
- Capacity becomes usable again once the accepted scans really finish.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import httpx
import pytest
import uvicorn

from ciberwebscan.api import concurrency
from ciberwebscan.export.models import AnalysisReport, ExportMeta

pytestmark = pytest.mark.integration

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("python_multipart")


def _free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def saturation_server(monkeypatch) -> Iterator[tuple[str, threading.Event]]:
    """Local API server with ``max_concurrent_scans=2`` and scans that block
    on an event controlled by the test."""
    from ciberwebscan.api.app import create_app
    from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
    from ciberwebscan.config.loader import reset_config

    monkeypatch.setenv("CIBERWEBSCAN_API_MAX_CONCURRENT_SCANS", "2")
    reset_config()
    concurrency.reset()

    release = threading.Event()

    def blocking_analyze(self, options):
        release.wait(timeout=30)
        result = MagicMock()
        result.success = True
        result.error = None
        result.export_path = None
        result.data = AnalysisReport(meta=ExportMeta(target_url=options.url))
        return result

    app = create_app()

    def mock_user() -> AuthenticatedUser:
        return AuthenticatedUser(
            identifier="test-user", auth_method="api_key", scopes=["read"]
        )

    app.dependency_overrides[get_current_user] = mock_user

    patcher = patch(
        "ciberwebscan.api.routes.analyze.AnalyzeService.analyze",
        blocking_analyze,
    )
    patcher.start()

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    else:
        patcher.stop()
        pytest.fail("Saturation test server failed to start within 5s")

    try:
        yield base, release
    finally:
        release.set()
        server.should_exit = True
        thread.join(timeout=5)
        patcher.stop()
        app.dependency_overrides.clear()
        concurrency.reset()


async def _wait_in_flight(expected: int, timeout: float = 5.0) -> None:
    """Poll the admission controller until in_flight reaches *expected*."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if concurrency.get_controller().in_flight == expected:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(
        f"in_flight never reached {expected}: "
        f"current={concurrency.get_controller().in_flight}"
    )


@pytest.mark.network
@pytest.mark.asyncio
async def test_saturation_rejects_early_and_health_stays_responsive(
    saturation_server: tuple[str, threading.Event],
):
    """With 2 slots and 3 scans: 2 run, the 3rd gets an immediate 429."""
    base, release = saturation_server

    async with httpx.AsyncClient(base_url=base, timeout=15.0) as client:
        scan_tasks = [
            asyncio.create_task(
                client.post("/api/analyze", json={"url": "https://example.com"})
            )
            for _ in range(2)
        ]
        await _wait_in_flight(2)

        # Both slots busy: /health must still answer promptly.
        health_start = time.perf_counter()
        health = await client.get("/health")
        health_latency = time.perf_counter() - health_start
        assert health.status_code == 200
        assert health_latency < 0.5, (
            f"/health blocked during saturation: {health_latency:.3f}s"
        )

        # The excess scan is rejected immediately, with a retry signal.
        rejected = await client.post(
            "/api/analyze", json={"url": "https://example.com"}
        )
        assert rejected.status_code == 429
        assert rejected.headers.get("Retry-After") is not None
        # Rejection must be fast (no queueing behind the blocked scans).
        assert rejected.elapsed.total_seconds() < 1.0

        # After the accepted scans finish, capacity is usable again.
        release.set()
        responses = await asyncio.gather(*scan_tasks)
        assert [r.status_code for r in responses] == [200, 200]
        await _wait_in_flight(0)

        follow_up = await client.post(
            "/api/analyze", json={"url": "https://example.com"}
        )
        assert follow_up.status_code == 200


@pytest.mark.network
@pytest.mark.asyncio
async def test_admission_slot_released_after_failed_scan(
    saturation_server: tuple[str, threading.Event],
):
    """A scan that finishes with an error returns its slot immediately."""
    base, release = saturation_server
    release.set()  # scans complete immediately (successful path here)

    async with httpx.AsyncClient(base_url=base, timeout=15.0) as client:
        for _ in range(3):
            response = await client.post(
                "/api/analyze", json={"url": "https://example.com"}
            )
            assert response.status_code == 200
        await _wait_in_flight(0)
