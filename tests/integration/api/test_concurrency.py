"""
Concurrency regression tests for event-loop blocking fix.

These tests verify that synchronous blocking operations in API routes
are executed in a threadpool and do not block the event loop,
allowing independent requests to continue responding.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest
import uvicorn

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("python_multipart")


def _free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def concurrency_server():
    """Start a patched API server for concurrency testing.

    Uses a dynamic port to avoid conflicts with other test servers.
    """
    from ciberwebscan.api.app import create_app
    from ciberwebscan.api.auth import AuthenticatedUser, get_current_user

    app = create_app()

    def mock_user() -> AuthenticatedUser:
        return AuthenticatedUser(
            identifier="test-user", auth_method="api_key", scopes=["read"]
        )

    app.dependency_overrides[get_current_user] = mock_user

    # Patch services to introduce controlled blocking (0.5s per request)
    def blocking_scrape(self, options):
        time.sleep(0.5)
        result = MagicMock()
        result.success = True
        result.data = None
        result.duration_seconds = 0.5
        return result

    def blocking_analyze(self, options):
        time.sleep(0.5)
        result = MagicMock()
        result.success = True
        result.data = MagicMock()
        result.data.meta = MagicMock()
        result.data.meta.target_url = options.url
        result.duration_seconds = 0.5
        return result

    def blocking_quick(self, options):
        time.sleep(0.5)
        result = MagicMock()
        result.success = True
        result.data = MagicMock()
        result.duration_seconds = 0.5
        result.warnings = []
        return result

    patchers = [
        patch("ciberwebscan.api.routes.scrape.ScrapeService.scrape", blocking_scrape),
        patch(
            "ciberwebscan.api.routes.analyze.AnalyzeService.analyze",
            blocking_analyze,
        ),
        patch("ciberwebscan.api.routes.quick.QuickService.quick_scan", blocking_quick),
    ]

    for p in patchers:
        p.start()

    port = _free_port()
    base = f"http://127.0.0.1:{port}"

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to be fully started (up to 5s)
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    else:
        for p in patchers:
            p.stop()
        pytest.fail("Concurrency test server failed to start within 5s")

    try:
        yield base
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        for p in patchers:
            p.stop()


@pytest.mark.asyncio
async def test_scrape_does_not_block_event_loop(concurrency_server: str):
    """Verify /api/scrape blocking op does not block /health."""
    async with httpx.AsyncClient(base_url=concurrency_server, timeout=10.0) as client:
        slow_task = asyncio.create_task(
            client.post(
                "/api/scrape",
                json={"url": "https://example.com", "dynamic": False},
            )
        )

        await asyncio.sleep(0.1)

        fast_start = time.perf_counter()
        fast_tasks = [client.get("/health") for _ in range(3)]
        fast_responses = await asyncio.gather(*fast_tasks)
        _ = time.perf_counter() - fast_start

        await slow_task

    fast_latencies = [r.elapsed.total_seconds() for r in fast_responses]
    max_latency = max(fast_latencies)

    assert max_latency < 0.5, (
        f"Fast /health requests were blocked: max latency {max_latency:.3f}s "
        f"(individual: {', '.join(f'{latency:.3f}' for latency in fast_latencies)})"
    )


@pytest.mark.asyncio
async def test_analyze_does_not_block_event_loop(concurrency_server: str):
    """Verify /api/analyze blocking op does not block /health."""
    async with httpx.AsyncClient(base_url=concurrency_server, timeout=10.0) as client:
        slow_task = asyncio.create_task(
            client.post(
                "/api/analyze",
                json={"url": "https://example.com", "ssl": True},
            )
        )

        await asyncio.sleep(0.1)

        fast_start = time.perf_counter()
        fast_tasks = [client.get("/health") for _ in range(3)]
        fast_responses = await asyncio.gather(*fast_tasks)
        _ = time.perf_counter() - fast_start

        await slow_task

    fast_latencies = [r.elapsed.total_seconds() for r in fast_responses]
    max_latency = max(fast_latencies)

    assert max_latency < 0.5, (
        f"Fast /health requests were blocked: max latency {max_latency:.3f}s "
        f"(individual: {', '.join(f'{latency:.3f}' for latency in fast_latencies)})"
    )


@pytest.mark.asyncio
async def test_quick_scan_does_not_block_event_loop(concurrency_server: str):
    """Verify /api/quick/scan blocking op does not block /health."""
    async with httpx.AsyncClient(base_url=concurrency_server, timeout=10.0) as client:
        slow_task = asyncio.create_task(
            client.post(
                "/api/quick/scan",
                json={"url": "https://example.com", "preset": "low"},
            )
        )

        await asyncio.sleep(0.1)

        fast_start = time.perf_counter()
        fast_tasks = [client.get("/health") for _ in range(3)]
        fast_responses = await asyncio.gather(*fast_tasks)
        _ = time.perf_counter() - fast_start

        await slow_task

    fast_latencies = [r.elapsed.total_seconds() for r in fast_responses]
    max_latency = max(fast_latencies)

    assert max_latency < 0.5, (
        f"Fast /health requests were blocked: max latency {max_latency:.3f}s "
        f"(individual: {', '.join(f'{latency:.3f}' for latency in fast_latencies)})"
    )


@pytest.mark.asyncio
async def test_multiple_endpoints_concurrent(concurrency_server: str):
    """Verify multiple different endpoints can run concurrently without blocking each other."""
    async with httpx.AsyncClient(base_url=concurrency_server, timeout=15.0) as client:
        scrape_task = asyncio.create_task(
            client.post(
                "/api/scrape",
                json={"url": "https://example.com", "dynamic": False},
            )
        )
        analyze_task = asyncio.create_task(
            client.post(
                "/api/analyze",
                json={"url": "https://example.com", "ssl": True},
            )
        )
        quick_task = asyncio.create_task(
            client.post(
                "/api/quick/scan",
                json={"url": "https://example.com", "preset": "low"},
            )
        )

        health_tasks = [client.get("/health") for _ in range(3)]

        start = time.perf_counter()
        scrape_resp, analyze_resp, quick_resp = await asyncio.gather(
            scrape_task, analyze_task, quick_task
        )
        health_resps = await asyncio.gather(*health_tasks)
        total_wall = time.perf_counter() - start

    assert total_wall < 1.5, (
        f"Endpoints appear to run sequentially: total wall time {total_wall:.3f}s"
    )

    health_latencies = [r.elapsed.total_seconds() for r in health_resps]
    max_health = max(health_latencies)
    assert max_health < 0.5, (
        f"Health checks blocked: max {max_health:.3f}s "
        f"({', '.join(f'{latency:.3f}' for latency in health_latencies)})"
    )
