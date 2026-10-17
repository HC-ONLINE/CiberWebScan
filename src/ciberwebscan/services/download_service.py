"""
Download service for managing file downloads and streaming.

Handles token generation, validation, expiration, and cleanup
of download tokens. Uses in-memory storage with thread-safe locks.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ciberwebscan.api.models.responses import DownloadInfo, DownloadTokenResponse
from ciberwebscan.config.loader import get_config
from ciberwebscan.services.base import BaseService, ServiceResult
from ciberwebscan.utils.async_runner import run_async
from ciberwebscan.utils.logging import mask_identifier
from ciberwebscan.utils.path_security import (
    PathTraversalError,
    resolve_and_validate_path,
)


class _DownloadRegistry:
    """In-memory registry for download tokens and file data.

    The registry keeps a full in-memory copy of every exported file, so it
    enforces a budget (``download.max_tokens`` / ``download.max_total_bytes``)
    to bound total process memory. Admission uses an atomic reserve-commit
    cycle: the byte reservation is taken *before* the file is read, so
    concurrent admissions can never oversubscribe the budget.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, DownloadInfo] = {}
        self._file_data: dict[str, bytes] = {}
        self._lock = threading.Lock()
        # Budget accounting (guarded by _lock):
        # - _total_bytes: bytes held by committed tokens.
        # - _reserved_bytes / _pending: bytes promised to in-flight
        #   admissions that have reserved budget but not yet read their file.
        self._total_bytes = 0
        self._reserved_bytes = 0
        self._pending = 0

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot of registry occupancy (tokens, bytes, in-flight work)."""
        with self._lock:
            return {
                "tokens": len(self._tokens),
                "total_bytes": self._total_bytes,
                "reserved_bytes": self._reserved_bytes,
                "pending": self._pending,
            }

    async def clear(self) -> None:
        """Drop every token and reset budget counters.

        Test-fixture support: production cleanup happens via
        ``cleanup_expired`` and ``delete``. Guards below clamp counters
        at zero, so a late release from an in-flight reservation is safe.
        """
        with self._lock:
            self._tokens.clear()
            self._file_data.clear()
            self._total_bytes = 0
            self._reserved_bytes = 0
            self._pending = 0

    async def reserve(
        self,
        size: int,
        max_tokens: int,
        max_total_bytes: int,
    ) -> bool:
        """Atomically reserve admission budget for a file of ``size`` bytes.

        Returns False when either budget dimension is exhausted. The
        reservation must be paired with ``commit`` (on success) or
        ``release_reservation`` (on any failure path).
        """
        with self._lock:
            if len(self._tokens) + self._pending >= max_tokens:
                return False
            if self._total_bytes + self._reserved_bytes + size > max_total_bytes:
                return False
            self._pending += 1
            self._reserved_bytes += size
            return True

    async def release_reservation(self, size: int) -> None:
        """Release an outstanding reservation after a failed admission."""
        with self._lock:
            self._pending = max(0, self._pending - 1)
            self._reserved_bytes = max(0, self._reserved_bytes - size)

    async def commit(
        self,
        token: str,
        info: DownloadInfo,
        file_data: bytes,
        reserved_size: int,
        max_total_bytes: int,
    ) -> bool:
        """Convert a reservation into a committed token entry.

        Re-checks the byte budget under the lock because the file may have
        grown between the ``stat()`` reservation and ``read_bytes()``; other
        concurrent commits may also have consumed the reserved slack.
        Returns False (caller must ``release_reservation``) when the budget
        no longer fits.
        """
        with self._lock:
            actual = len(file_data)
            if self._total_bytes + actual > max_total_bytes:
                return False
            self._pending = max(0, self._pending - 1)
            self._reserved_bytes = max(0, self._reserved_bytes - reserved_size)
            self._insert_locked(token, info, file_data)
            return True

    def _insert_locked(self, token: str, info: DownloadInfo, file_data: bytes) -> None:
        """Insert or overwrite a token, keeping ``_total_bytes`` exact."""
        previous = self._file_data.get(token)
        if previous is not None:
            self._total_bytes -= len(previous)
        self._tokens[token] = info
        self._file_data[token] = file_data
        self._total_bytes += len(file_data)

    async def store(
        self,
        token: str,
        info: DownloadInfo,
        file_data: bytes,
    ) -> None:
        """Store token with metadata and file data (no budget enforcement)."""
        with self._lock:
            self._insert_locked(token, info, file_data)

    async def get_info(self, token: str) -> DownloadInfo | None:
        """Retrieve token metadata."""
        with self._lock:
            return self._tokens.get(token)

    async def get_file_data(self, token: str) -> bytes | None:
        """Retrieve file data."""
        with self._lock:
            return self._file_data.get(token)

    async def update_attempts(self, token: str) -> bool:
        """
        Decrement remaining attempts and return True if still valid.
        Returns False if max attempts exceeded.
        """
        with self._lock:
            if token not in self._tokens:
                return False
            info = self._tokens[token]
            if info.attempts_remaining <= 0:
                return False
            info.attempts_remaining -= 1
            self._tokens[token] = info
            return True

    async def restore_attempt(self, token: str, max_attempts: int) -> bool:
        """
        Return a previously consumed attempt to a token.

        Never recreates a deleted token (late refunds after a concurrent
        success or TTL cleanup are silently dropped) and never lets the
        counter exceed ``max_attempts`` (defensive cap against unpaired
        refunds or a runtime-lowered ``download.max_retries``).

        Args:
            token: Download token whose attempt should be restored.
            max_attempts: Upper bound enforced on the attempts counter.

        Returns:
            True if an attempt was restored, False otherwise.
        """
        with self._lock:
            info = self._tokens.get(token)
            if info is None:
                return False
            if info.attempts_remaining >= max_attempts:
                return False
            info.attempts_remaining += 1
            self._tokens[token] = info
            return True

    async def delete(self, token: str) -> bool:
        """Delete token and associated file data."""
        with self._lock:
            if token not in self._tokens:
                return False
            del self._tokens[token]
            file_data = self._file_data.pop(token, None)
            if file_data is not None:
                self._total_bytes = max(0, self._total_bytes - len(file_data))
            return True

    async def cleanup_expired(self) -> int:
        """Delete all expired tokens. Returns count of deleted tokens."""
        with self._lock:
            now = datetime.now(timezone.utc)
            expired_tokens = [
                token for token, info in self._tokens.items() if info.expires_at <= now
            ]
            for token in expired_tokens:
                del self._tokens[token]
                file_data = self._file_data.pop(token, None)
                if file_data is not None:
                    self._total_bytes = max(0, self._total_bytes - len(file_data))
            return len(expired_tokens)

    async def get_expired_count(self) -> int:
        """Get count of expired tokens without deleting them."""
        with self._lock:
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
            file_path: Path to file to download. Must be within allowed directories.
            user_id: ID of user requesting download
            file_format: Format of the exported file (json/jsonl/csv/html)

        Returns:
            ServiceResult with DownloadTokenResponse containing token and expiration
        """
        try:
            config = get_config()

            # Single admission gate for every consumer (helper, scrape/batch,
            # direct service use): no tokens may exist while downloads are off.
            if not config.download.enabled:
                self.logger.info(
                    "Download token not generated: downloads are disabled "
                    "(download.enabled=false)"
                )
                return ServiceResult(
                    success=False,
                    error="Download service is disabled",
                )

            # Validate path to prevent traversal attacks
            output_base = Path(config.export.output_dir)
            if not output_base.is_absolute():
                # Relative output_dir resolves under ~/.ciberwebscan/exports/
                # to avoid CWD-dependent sandbox boundaries
                output_base = Path.home() / ".ciberwebscan" / "exports"

            try:
                validated_path = resolve_and_validate_path(file_path, output_base)
            except PathTraversalError as e:
                self.logger.warning(f"Path traversal attempt blocked in download: {e}")
                return ServiceResult(
                    success=False,
                    error="Access denied: invalid file path",
                )

            # Validate file exists
            if not validated_path.exists():
                return ServiceResult(
                    success=False,
                    error=f"File not found: {validated_path}",
                )

            file_path = validated_path

            # Size check on metadata first: never load a file that is already
            # known to exceed the per-file limit (read_bytes() would copy the
            # whole file into RAM before the check could reject it).
            try:
                size_bytes = file_path.stat().st_size
            except OSError as e:
                self.logger.error(f"Unable to stat export file: {e}")
                return ServiceResult(
                    success=False,
                    error=f"Unable to read file size: {file_path}",
                )

            file_size_mb = size_bytes / (1024 * 1024)
            if file_size_mb > config.download.max_file_size_mb:
                return ServiceResult(
                    success=False,
                    error=f"File size {file_size_mb:.2f}MB exceeds limit of {config.download.max_file_size_mb}MB",
                )

            # Atomic budget reservation BEFORE reading: concurrent admissions
            # (up to the server threadpool width) can never jointly hold more
            # than the configured memory budget.
            reserved = run_async(
                _registry.reserve(
                    size_bytes,
                    config.download.max_tokens,
                    config.download.max_total_bytes,
                )
            )
            if not reserved:
                self.logger.warning(
                    f"Download token not created for user "
                    f"{mask_identifier(user_id)}: registry budget exhausted "
                    f"(max_tokens={config.download.max_tokens}, "
                    f"max_total_bytes={config.download.max_total_bytes})"
                )
                return ServiceResult(
                    success=False,
                    error="Download storage quota exceeded: token not created",
                )

            committed = False
            try:
                # Read file data (reservation covers this allocation)
                file_data = file_path.read_bytes()
                file_size_mb = len(file_data) / (1024 * 1024)

                # Defensive re-check: the file may have grown between stat()
                # and read_bytes() (TOCTOU); commit re-checks the budget too.
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

                # Commit the reservation (re-checks budget under the lock)
                committed = run_async(
                    _registry.commit(
                        token,
                        info,
                        file_data,
                        size_bytes,
                        config.download.max_total_bytes,
                    )
                )
                if not committed:
                    self.logger.warning(
                        f"Download token not created for user "
                        f"{mask_identifier(user_id)}: file grew beyond the "
                        f"reserved budget"
                    )
                    return ServiceResult(
                        success=False,
                        error="Download storage quota exceeded: token not created",
                    )
            finally:
                if not committed:
                    # Failure path (size re-check, read error, commit refusal):
                    # hand the reservation back so the budget never leaks.
                    run_async(_registry.release_reservation(size_bytes))

            response = DownloadTokenResponse(
                token=token,
                expires_at=expires_at,
            )

            self.logger.info(
                f"Generated download token {token} for user "
                f"{mask_identifier(user_id)} "
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
            info = run_async(_registry.get_info(token))

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
                    f"Unauthorized download attempt: "
                    f"token owner {mask_identifier(info.user_id)}, "
                    f"requester {mask_identifier(user_id)}"
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
            still_valid = run_async(_registry.update_attempts(token))
            if not still_valid:
                return ServiceResult(
                    success=False,
                    error="Download attempts exhausted",
                )

            # info is a live reference already decremented in place by
            # update_attempts; subtracting again would under-report by one.
            remaining = info.attempts_remaining
            self.logger.info(
                f"Valid download request for token {token} "
                f"({remaining} attempts remaining)"
            )

            return ServiceResult(success=True, data=True)

        except Exception as e:
            self.logger.error(f"Error validating download request: {e}")
            return ServiceResult(success=False, error=str(e))

    def restore_attempt(self, token: str) -> ServiceResult[bool]:
        """
        Return a consumed attempt after a server-side download failure.

        Mirrors the reservation made by ``validate_download_request``: the
        attempt is only restored when the token still exists and the counter
        would stay within ``download.max_retries``. A deleted token is never
        recreated.

        The cap uses the configuration value at call time: if
        ``download.max_retries`` is lowered at runtime, refunds on tokens
        created under a higher value may be refused, leaving the counter at
        its (lower) current value. This fails safe — attempts are never
        inflated beyond the configured limit.

        Args:
            token: Download token whose attempt should be restored.

        Returns:
            ServiceResult with True if an attempt was restored.
        """
        try:
            max_attempts = get_config().download.max_retries
            restored = run_async(_registry.restore_attempt(token, max_attempts))
            if restored:
                self.logger.info(f"Attempt restored for token {token}")
                return ServiceResult(success=True, data=True)
            self.logger.warning(
                f"Attempt not restored for token {token}: token gone or "
                f"attempts already at the configured maximum"
            )
            return ServiceResult(success=False, error="Attempt not restored")
        except Exception as e:
            self.logger.error(f"Error restoring attempt for token {token}: {e}")
            return ServiceResult(success=False, error=str(e))

    def get_info(self, token: str) -> ServiceResult[DownloadInfo]:
        """
        Retrieve metadata (including file_format) for a download token.

        Read-only: expiration, ownership and attempt checks are the
        caller's responsibility (``validate_download_request``), which
        runs before any use of this metadata.

        Args:
            token: Download token

        Returns:
            ServiceResult with the token's DownloadInfo, or a failure
            result when the token no longer exists.
        """
        try:
            info = run_async(_registry.get_info(token))
            if info is None:
                return ServiceResult(success=False, error="Token not found")
            return ServiceResult(success=True, data=info)
        except Exception as e:
            self.logger.error(f"Error getting token info: {e}")
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
            file_data = run_async(_registry.get_file_data(token))

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
            count = run_async(_registry.cleanup_expired())
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
            result = run_async(_registry.delete(token))
            if result:
                self.logger.info(f"Token deleted after successful download: {token}")
                return ServiceResult(success=True, data=True)
            else:
                self.logger.error(f"Token not found for deletion: {token}")
                return ServiceResult(success=False, error="Token not found")
        except Exception as e:
            self.logger.error(f"Error deleting token {token}: {e}")
            return ServiceResult(success=False, error=str(e))
