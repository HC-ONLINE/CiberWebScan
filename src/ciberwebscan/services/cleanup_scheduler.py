"""
Background job scheduler for download token cleanup.

Handles periodic cleanup of expired download tokens and associated file data.
Runs as a background task in the API lifetime events.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ciberwebscan.config.loader import get_config
from ciberwebscan.services.download_service import DownloadService

logger = logging.getLogger(__name__)


class DownloadCleanupScheduler:
    """Scheduler for cleaning up expired download tokens."""

    def __init__(self) -> None:
        """Initialize the scheduler."""
        self._task: asyncio.Task[Any] | None = None
        self._running = False
        self._service = DownloadService()

    def start(self) -> None:
        """Start the cleanup scheduler."""
        if self._running:
            logger.warning("Cleanup scheduler already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Download cleanup scheduler started")

    def stop(self) -> None:
        """Stop the cleanup scheduler."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            logger.info("Download cleanup scheduler stopped")

    async def _run_loop(self) -> None:
        """Main scheduler loop - runs cleanup at configured intervals."""
        config = get_config()
        interval = config.download.cleanup_interval_seconds

        while self._running:
            try:
                await asyncio.sleep(interval)

                if not self._running:
                    break

                # Run cleanup
                result = self._service.cleanup_expired_tokens()

                if result.success:
                    count = result.data or 0
                    if count > 0:
                        logger.info(
                            f"Cleanup job: removed {count} expired download tokens"
                        )
                else:
                    logger.error(f"Cleanup job failed: {result.error}")

            except asyncio.CancelledError:
                logger.debug("Cleanup scheduler task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in cleanup scheduler loop: {e}", exc_info=True)
                # Continue running despite errors
                continue


# Global scheduler instance
_scheduler: DownloadCleanupScheduler | None = None


def get_scheduler() -> DownloadCleanupScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = DownloadCleanupScheduler()
    return _scheduler
