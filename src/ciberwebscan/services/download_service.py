"""
Download service for managing file downloads and streaming.

Handles token generation, validation, expiration, and cleanup
of download tokens. Uses in-memory storage with asyncio locks.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ciberwebscan.api.models.responses import DownloadInfo, DownloadTokenResponse
from ciberwebscan.config.loader import get_config
from ciberwebscan.services.base import BaseService, ServiceResult


def _run_async(coro):
    """
    Run async coroutine safely, handling both async and sync contexts
    In async context (FastAPI): uses ThreadPoolExecutor to avoid event loop issues
    In sync context: uses asyncio.run()
    """
    try:
        asyncio.get_running_loop()
        # We're in an async context, use thread executor
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(lambda: asyncio.run(coro))
            return future.result(timeout=30)
    except RuntimeError:
        # No event loop running, safe to use asyncio.run()
        return asyncio.run(coro)


class _DownloadRegistry:
    """In-memory registry for download tokens and file data."""

    def __init__(self) -> None:
        self._tokens: dict[str, DownloadInfo] = {}
        self._file_data: dict[str, bytes] = {}
        self._lock = asyncio.Lock()

    async def store(
        self,
        token: str,
        info: DownloadInfo,
        file_data: bytes,
    ) -> None:
        """Store token with metadata and file data."""
        async with self._lock:
            self._tokens[token] = info
            self._file_data[token] = file_data

    async def get_info(self, token: str) -> DownloadInfo | None:
        """Retrieve token metadata."""
        async with self._lock:
            return self._tokens.get(token)

    async def get_file_data(self, token: str) -> bytes | None:
        """Retrieve file data."""
        async with self._lock:
            return self._file_data.get(token)

    async def update_attempts(self, token: str) -> bool:
        """
        Decrement remaining attempts and return True if still valid.
        Returns False if max attempts exceeded.
        """
        async with self._lock:
            if token not in self._tokens:
                return False
            info = self._tokens[token]
            if info.attempts_remaining <= 0:
                return False
            info.attempts_remaining -= 1
            self._tokens[token] = info
            return True

    async def delete(self, token: str) -> bool:
        """Delete token and associated file data."""
        async with self._lock:
            if token not in self._tokens:
                return False
            del self._tokens[token]
            self._file_data.pop(token, None)
            return True

    async def cleanup_expired(self) -> int:
        """Delete all expired tokens. Returns count of deleted tokens."""
        async with self._lock:
            now = datetime.now(timezone.utc)
            expired_tokens = [
                token for token, info in self._tokens.items() if info.expires_at <= now
            ]
            for token in expired_tokens:
                del self._tokens[token]
                self._file_data.pop(token, None)
            return len(expired_tokens)

    async def get_expired_count(self) -> int:
        """Get count of expired tokens without deleting them."""
        async with self._lock:
            now = datetime.now(timezone.utc)
            return sum(1 for info in self._tokens.values() if info.expires_at <= now)


# Global registry instance
_registry = _DownloadRegistry()


class DownloadService(BaseService):
    """Service for managing file downloads and streaming."""

    def generate_download_token(
        self,
        file_path: Path | str,
        user_id: str,
        file_format: str = "json",
    ) -> ServiceResult[DownloadTokenResponse]:
        """
        Generate a download token for a file.

        Args:
            file_path: Path to file to download
            user_id: ID of user requesting download
            file_format: Format of the exported file (json/jsonl/csv)

        Returns:
            ServiceResult with DownloadTokenResponse containing token and URL
        """
        try:
            config = get_config()
            file_path = Path(file_path)

            # Validate file exists
            if not file_path.exists():
                return ServiceResult(
                    success=False,
                    error=f"File not found: {file_path}",
                )

            # Read file data
            file_data = file_path.read_bytes()
            file_size_mb = len(file_data) / (1024 * 1024)

            # Validate size
            if file_size_mb > config.download.max_file_size_mb:
                return ServiceResult(
                    success=False,
                    error=f"File size {file_size_mb:.2f}MB exceeds limit of {config.download.max_file_size_mb}MB",
                )

            # Generate token
            token = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=config.download.retention_seconds)

            # Create metadata
            info = DownloadInfo(
                token=token,
                user_id=user_id,
                file_size_bytes=len(file_data),
                created_at=now,
                expires_at=expires_at,
                attempts_remaining=config.download.max_retries,
                file_format=file_format,
            )

            # Store token (async operation)
            _run_async(_registry.store(token, info, file_data))

            download_url = f"/api/v1/download/{token}"
            response = DownloadTokenResponse(
                token=token,
                expires_at=expires_at,
                download_url=download_url,
            )

            self.logger.info(
                f"Generated download token {token} for user {user_id} "
                f"(file size: {file_size_mb:.2f}MB, expires: {expires_at.isoformat()})"
            )

            return ServiceResult(success=True, data=response)

        except Exception as e:
            self.logger.error(f"Error generating download token: {e}")
            return ServiceResult(success=False, error=str(e))

    def validate_download_request(
        self,
        token: str,
        user_id: str,
    ) -> ServiceResult[bool]:
        """
        Validate a download request token.

        Args:
            token: Download token to validate
            user_id: ID of user requesting download

        Returns:
            ServiceResult with True if valid, False otherwise
        """
        try:
            config = get_config()

            # Get token info
            info = _run_async(_registry.get_info(token))

            if info is None:
                return ServiceResult(success=False, error="Token not found")

            # Check expiration
            now = datetime.now(timezone.utc)
            if info.expires_at <= now:
                self.logger.warning(f"Expired token accessed: {token}")
                return ServiceResult(success=False, error="Token expired")

            # Check user match if required
            if config.download.require_same_user and info.user_id != user_id:
                self.logger.warning(
                    f"Unauthorized download attempt: token owner {info.user_id}, "
                    f"requester {user_id}"
                )
                return ServiceResult(
                    success=False,
                    error="Unauthorized: token belongs to different user",
                )

            # Check attempts remaining
            if info.attempts_remaining <= 0:
                self.logger.warning(f"Max retries exceeded for token: {token}")
                return ServiceResult(
                    success=False,
                    error="Maximum download attempts exceeded",
                )

            # Decrement attempts
            still_valid = _run_async(_registry.update_attempts(token))
            if not still_valid:
                return ServiceResult(
                    success=False,
                    error="Download attempts exhausted",
                )

            remaining = info.attempts_remaining - 1
            self.logger.info(
                f"Valid download request for token {token} "
                f"({remaining} attempts remaining)"
            )

            return ServiceResult(success=True, data=True)

        except Exception as e:
            self.logger.error(f"Error validating download request: {e}")
            return ServiceResult(success=False, error=str(e))

    def get_file_stream(
        self,
        token: str,
    ) -> ServiceResult[Iterator[bytes]]:
        """
        Get file data as a streaming iterator.

        Args:
            token: Download token

        Returns:
            ServiceResult with Iterator yielding file chunks
        """
        try:
            config = get_config()
            file_data = _run_async(_registry.get_file_data(token))

            if file_data is None:
                return ServiceResult(
                    success=False,
                    error="File data not found",
                )

            def chunk_iterator() -> Iterator[bytes]:
                """Yield file data in chunks."""
                chunk_size = config.download.stream_chunk_size
                for i in range(0, len(file_data), chunk_size):
                    yield file_data[i : i + chunk_size]

            return ServiceResult(success=True, data=chunk_iterator())

        except Exception as e:
            self.logger.error(f"Error getting file stream: {e}")
            return ServiceResult(success=False, error=str(e))

    def cleanup_expired_tokens(self) -> ServiceResult[int]:
        """
        Delete all expired tokens. Typically called by background job.

        Returns:
            ServiceResult with count of tokens cleaned up
        """
        try:
            count = _run_async(_registry.cleanup_expired())
            if count > 0:
                self.logger.info(f"Cleanup job: deleted {count} expired tokens")
            return ServiceResult(success=True, data=count)
        except Exception as e:
            self.logger.error(f"Error during token cleanup: {e}")
            return ServiceResult(success=False, error=str(e), data=0)

    def delete_token(self, token: str) -> ServiceResult[bool]:
        """
        Delete a token and its associated file data after download completes.

        Args:
            token: Download token to delete

        Returns:
            ServiceResult with success status
        """
        try:
            result = _run_async(_registry.delete(token))
            if result:
                self.logger.info(f"Token deleted after successful download: {token}")
                return ServiceResult(success=True, data=True)
            else:
                self.logger.error(f"Token not found for deletion: {token}")
                return ServiceResult(success=False, error="Token not found")
        except Exception as e:
            self.logger.error(f"Error deleting token {token}: {e}")
            return ServiceResult(success=False, error=str(e))
