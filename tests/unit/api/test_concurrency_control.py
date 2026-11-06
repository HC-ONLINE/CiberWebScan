"""
Unit tests for scan admission control, deadlines and threadpool sizing (BUG-013).

These tests pin the concurrency contract of the scan endpoints:

- Admission rejects the excess with 429 instead of queueing unboundedly.
- A deadline answers 504 on time but keeps the admission slot until the
  non-cancellable worker thread really finishes (no premature release).
- Slots are released on success, error and timeout.
- The shared AnyIO threadpool is sized from configuration at startup.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import anyio.to_thread
import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api import concurrency
from ciberwebscan.api.app import create_app
from ciberwebscan.config.loader import reset_config
from ciberwebscan.export.models import AnalysisReport, ExportMeta

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def clean_concurrency_state() -> Iterator[None]:
    """Isolate the module-level controller/limiter between tests."""
    concurrency.reset()
    yield
    concurrency.reset()


@pytest.fixture
def limit_one_scan(monkeypatch) -> None:
    """Configure the app for at most one scan in flight."""
    monkeypatch.setenv("CIBERWEBSCAN_API_MAX_CONCURRENT_SCANS", "1")
    reset_config()


@pytest.fixture
def one_second_deadline(monkeypatch) -> None:
    """Configure a 1s scan deadline."""
    monkeypatch.setenv("CIBERWEBSCAN_API_SCAN_TIMEOUT_SECONDS", "1")
    reset_config()


def _make_client() -> TestClient:
    """Build an app + TestClient with authentication overridden."""
    from ciberwebscan.api.auth import AuthenticatedUser, get_current_user

    app = create_app()

    def mock_user() -> AuthenticatedUser:
        return AuthenticatedUser(
            identifier="test-user", auth_method="api_key", scopes=["read"]
        )

    app.dependency_overrides[get_current_user] = mock_user
    return TestClient(app)


def _successful_result(url: str) -> MagicMock:
    result = MagicMock()
    result.success = True
    result.error = None
    result.export_path = None
    result.data = AnalysisReport(meta=ExportMeta(target_url=url))
    return result


def _wait_in_flight(expected: int, timeout: float = 5.0) -> None:
    """Poll the controller until in_flight reaches *expected*."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if concurrency.get_controller().in_flight == expected:
            return
        time.sleep(0.01)
    raise AssertionError(
        f"in_flight never reached {expected}: "
        f"current={concurrency.get_controller().in_flight}"
    )


class TestScanAdmissionController:
    """Pure unit tests for the admission counter."""

    def test_acquire_up_to_limit(self):
        controller = concurrency.ScanAdmissionController(2)
        assert controller.try_acquire() is True
        assert controller.try_acquire() is True
        assert controller.try_acquire() is False
        assert controller.in_flight == 2
        assert controller.limit == 2

    def test_release_restores_capacity(self):
        controller = concurrency.ScanAdmissionController(1)
        assert controller.try_acquire() is True
        controller.release()
        assert controller.in_flight == 0
        assert controller.try_acquire() is True

    def test_release_without_acquire_is_ignored(self):
        controller = concurrency.ScanAdmissionController(1)
        controller.release()
        assert controller.in_flight == 0

    def test_limit_must_be_positive(self):
        with pytest.raises(ValueError):
            concurrency.ScanAdmissionController(0)


class TestScanAdmissionHTTP:
    """Route-level behaviour of admission control and deadlines."""

    def test_saturated_scan_rejected_with_429(self, limit_one_scan: None):
        """The second concurrent scan gets 429 + Retry-After, not a queue."""
        started = threading.Event()
        release = threading.Event()

        def blocking_analyze(self, options):
            started.set()
            release.wait(timeout=10)
            return _successful_result(options.url)

        client = _make_client()
        responses: list = []
        try:
            with patch(
                "ciberwebscan.api.routes.analyze.AnalyzeService.analyze",
                blocking_analyze,
            ):
                first = threading.Thread(
                    target=lambda: responses.append(
                        client.post("/api/analyze", json={"url": "https://example.com"})
                    )
                )
                first.start()
                assert started.wait(timeout=5), "first scan never started"

                second = client.post(
                    "/api/analyze", json={"url": "https://example.com"}
                )
                assert second.status_code == 429
                assert second.headers.get("Retry-After") is not None

                release.set()
                first.join(timeout=10)
                assert not first.is_alive()
                assert responses[0].status_code == 200

                # Capacity is reusable once the scan really finished.
                _wait_in_flight(0)
        finally:
            release.set()
            client.app.dependency_overrides.clear()

    def test_deadline_answers_504_but_slot_held_until_work_ends(
        self, one_second_deadline: None
    ):
        """504 is answered on time; the slot is released only when the
        blocking work actually finishes (honest accounting)."""
        started = threading.Event()
        release = threading.Event()

        def slow_analyze(self, options):
            started.set()
            release.wait(timeout=10)
            return _successful_result(options.url)

        client = _make_client()
        try:
            with (
                patch(
                    "ciberwebscan.api.routes.analyze.AnalyzeService.analyze",
                    slow_analyze,
                ),
                # Used as a context manager so the underlying event loop
                # (portal) stays alive across the request. Without it,
                # TestClient tears the portal down per request and cancels
                # the abandoned worker task, releasing the slot early —
                # an artifact of the test harness, not of the design.
                client,
            ):
                began = time.monotonic()
                response = client.post(
                    "/api/analyze", json={"url": "https://example.com"}
                )
                elapsed = time.monotonic() - began

                assert response.status_code == 504
                assert elapsed < 5, f"deadline did not fire promptly: {elapsed:.1f}s"
                assert started.is_set()

                # The worker thread is still alive: the slot must NOT be free.
                assert concurrency.get_controller().in_flight == 1

                release.set()
                _wait_in_flight(0, timeout=10)
        finally:
            release.set()
            client.app.dependency_overrides.clear()

    def test_slot_released_after_scan_error(self, limit_one_scan: None):
        """An exception inside the scan releases the admission slot."""

        def failing_analyze(self, options):
            raise RuntimeError("boom")

        client = _make_client()
        try:
            with patch(
                "ciberwebscan.api.routes.analyze.AnalyzeService.analyze",
                failing_analyze,
            ):
                response = client.post(
                    "/api/analyze", json={"url": "https://example.com"}
                )
                assert response.status_code == 500
                _wait_in_flight(0)
        finally:
            client.app.dependency_overrides.clear()


class TestThreadpoolSizing:
    """The shared AnyIO threadpool size comes from configuration."""

    def test_default_limiter_sized_from_config(self, monkeypatch):
        monkeypatch.setenv("CIBERWEBSCAN_API_SYNC_THREADPOOL_TOKENS", "7")
        reset_config()
        app = create_app()
        with TestClient(app) as client:
            limiter = client.portal.call(anyio.to_thread.current_default_thread_limiter)
            assert limiter.total_tokens == 7

    def test_scan_limiter_matches_configured_limit(self, limit_one_scan: None):
        assert concurrency.get_scan_limiter().total_tokens == 1
        assert concurrency.get_controller().limit == 1
