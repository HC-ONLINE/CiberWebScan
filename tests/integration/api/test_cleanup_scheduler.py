"""
Integration tests for download cleanup scheduler.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ciberwebscan.services.cleanup_scheduler import (
    DownloadCleanupScheduler,
    get_scheduler,
)
from ciberwebscan.services.download_service import DownloadService

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def scheduler() -> DownloadCleanupScheduler:
    """Create a scheduler instance."""
    return DownloadCleanupScheduler()


@pytest.fixture
def test_file() -> Path:
    """Create a temporary test file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        f.write('{"test": "data"}')
        return Path(f.name)


# =============================================================================
# Tests
# =============================================================================


class TestDownloadCleanupScheduler:
    """Tests for cleanup scheduler."""

    @pytest.mark.asyncio
    async def test_scheduler_starts_and_stops(
        self, scheduler: DownloadCleanupScheduler
    ):
        """Scheduler starts and stops correctly."""
        scheduler.start()
        assert scheduler._running is True
        assert scheduler._task is not None

        scheduler.stop()
        assert scheduler._running is False

    def test_scheduler_singleton_pattern(self):
        """Scheduler follows singleton pattern via get_scheduler."""
        sched1 = get_scheduler()
        sched2 = get_scheduler()

        assert sched1 is sched2, "Should return same instance"

    def test_cleanup_service_integration(self, test_file: Path):
        """Scheduler integrates with DownloadService."""
        service = DownloadService()

        # Generate token
        result = service.generate_download_token(
            file_path=test_file, user_id="test_user", file_format="json"
        )

        assert result.success
        assert result.data.token is not None

        # Cleanup should work
        cleanup_result = service.cleanup_expired_tokens()
        assert cleanup_result.success
