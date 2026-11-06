"""
Unit tests for the download cleanup scheduler (BUG-013).

The scheduler used to call the (blocking) cleanup service directly on the
event loop, freezing every pending request for the duration of the sweep.
These tests pin that the cleanup work runs off the event loop.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from ciberwebscan.services.cleanup_scheduler import DownloadCleanupScheduler

pytestmark = pytest.mark.unit


@pytest.fixture
def fast_scheduler() -> Iterator[DownloadCleanupScheduler]:
    """A scheduler with a 10ms interval and a mocked cleanup service.

    The mocked ``cleanup_expired_tokens`` records whether an event loop was
    running in the thread that executed it.
    """
    with (
        patch("ciberwebscan.services.cleanup_scheduler.get_config") as mock_config,
        patch(
            "ciberwebscan.services.cleanup_scheduler.DownloadService"
        ) as mock_service_class,
    ):
        mock_config.return_value.download.cleanup_interval_seconds = 0.01

        service = mock_service_class.return_value
        state = {"loop_running": None, "calls": 0, "thread_id": None}

        def recording_cleanup():
            state["calls"] += 1
            state["thread_id"] = threading.get_ident()
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                state["loop_running"] = False
            else:
                state["loop_running"] = True
            result = MagicMock()
            result.success = True
            result.data = 0
            return result

        service.cleanup_expired_tokens.side_effect = recording_cleanup
        scheduler = DownloadCleanupScheduler()
        scheduler._test_state = state  # type: ignore[attr-defined]
        yield scheduler
        scheduler.stop()


class TestCleanupSchedulerEventLoop:
    """Cleanup must never execute on the event loop thread."""

    @pytest.mark.asyncio
    async def test_cleanup_runs_off_the_event_loop(
        self, fast_scheduler: DownloadCleanupScheduler
    ):
        fast_scheduler.start()
        assert fast_scheduler._running is True

        # Wait (deterministically polling the recorded state) for the
        # first cleanup pass to happen off-loop.
        state = fast_scheduler._test_state  # type: ignore[attr-defined]
        for _ in range(500):
            if state["calls"] > 0:
                break
            await asyncio.sleep(0.01)
        fast_scheduler.stop()

        assert state["calls"] > 0, "cleanup never ran"
        assert state["loop_running"] is False, (
            "cleanup executed with a running event loop in its thread: "
            "it would block the event loop (regression of BUG-013)"
        )
        assert state["thread_id"] != threading.get_ident(), (
            "cleanup ran on the test's event-loop thread"
        )
