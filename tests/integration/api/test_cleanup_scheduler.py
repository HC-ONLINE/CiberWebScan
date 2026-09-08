"""
Integration tests for download cleanup scheduler.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

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
def test_file(tmp_path: Path) -> Path:
    """Create a temporary test file inside the mock export dir."""
    test_file = tmp_path / "test_data.json"
    test_file.write_text('{"test": "data"}')
    return test_file


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

    def test_cleanup_service_integration(self, test_file: Path, tmp_path: Path):
        """Scheduler integrates with DownloadService."""
        with patch("ciberwebscan.services.download_service.get_config") as mock_cfg:
            mock_cfg.return_value.export.output_dir = str(tmp_path)
            mock_cfg.return_value.download.max_file_size_mb = 10
            mock_cfg.return_value.download.retention_seconds = 3600
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
