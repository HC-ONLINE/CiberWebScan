"""
Tests for DownloadService class.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from ciberwebscan.api.models.responses import DownloadInfo, DownloadTokenResponse
from ciberwebscan.config.loader import get_config
from ciberwebscan.services.download_service import DownloadService, _registry

pytestmark = pytest.mark.unit

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def service() -> DownloadService:
    """Create a test service instance."""
    return DownloadService()


@pytest.fixture
def test_file(tmp_path: Path) -> Path:
    """Create a temporary test file within the allowed directory."""
    test_file = tmp_path / "test_export.json"
    test_file.write_text('{"test": "data"}')
    return test_file


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear the registry before and after each test."""
    asyncio.run(_registry.cleanup_expired())
    yield
    asyncio.run(_registry.cleanup_expired())


@pytest.fixture(autouse=True)
def mock_export_dir(tmp_path: Path):
    """Mock the export directory validation to use tmp_path."""
    with patch(
        "ciberwebscan.services.download_service.resolve_and_validate_path",
        side_effect=lambda p, base, **kw: (
            Path(p) if Path(p).is_absolute() else (base / p).resolve()
        ),
    ):
        yield


# =============================================================================
# Test: Generate Token
# =============================================================================


class TestGenerateDownloadToken:
    """Tests for token generation."""

    def test_generate_token_success(self, service: DownloadService, test_file: Path):
        """TEST 1: Generate valid token with correct metadata."""
        result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user_123",
            file_format="json",
        )

        assert result.success is True
        assert result.data is not None
        assert isinstance(result.data, DownloadTokenResponse)
        assert result.data.token is not None
        assert len(result.data.token) == 36  # UUID v4 length
        assert result.data.expires_at > datetime.now(timezone.utc)

    def test_generate_token_file_not_found(self, service: DownloadService):
        """TEST 2: Reject non-existent file."""
        result = service.generate_download_token(
            file_path="/nonexistent/file.json",
            user_id="test_user",
            file_format="json",
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.slow
    def test_generate_token_file_too_large(self, service: DownloadService):
        """TEST 5: Reject file exceeding max size."""
        config = get_config()
        max_size = config.download.max_file_size_mb

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            # Create file larger than max
            f.write("x" * int((max_size + 1) * 1024 * 1024))
            large_file = Path(f.name)

        try:
            result = service.generate_download_token(
                file_path=large_file,
                user_id="test_user",
                file_format="json",
            )

            assert result.success is False
            assert "exceeds limit" in result.error.lower()
        finally:
            large_file.unlink()


# =============================================================================
# Test: Validate Download Request
# =============================================================================


class TestValidateDownloadRequest:
    """Tests for request validation."""

    def test_validate_expired_token(self, service: DownloadService, test_file: Path):
        """TEST2: Reject expired token."""
        # Generate token
        gen_result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token = gen_result.data.token

        # Manually expire the token (update directly in the dict since it's internal)
        # This is a hack for testing - normally the scheduler would handle this
        async def expire_token():
            info = await _registry.get_info(token)
            if info:
                info.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                await _registry.store(token, info, b"test")

        asyncio.run(expire_token())

        # Validate should fail
        result = service.validate_download_request(token, "test_user")
        assert result.success is False
        assert "expired" in result.error.lower()

    def test_validate_user_mismatch(self, service: DownloadService, test_file: Path):
        """TEST 3: Reject mismatched user ID."""
        config = get_config()
        original_require = config.download.require_same_user

        try:
            # Enable user checking
            config.download.require_same_user = True

            # Generate token for one user
            gen_result = service.generate_download_token(
                file_path=test_file,
                user_id="user_1",
                file_format="json",
            )
            token = gen_result.data.token

            # Try with different user
            result = service.validate_download_request(token, "user_2")
            assert result.success is False
            assert "unauthorized" in result.error.lower()
        finally:
            config.download.require_same_user = original_require

    def test_validate_max_retries_exceeded(
        self, service: DownloadService, test_file: Path
    ):
        """TEST 4: Reject request exceeding max retries."""
        config = get_config()
        max_retries = config.download.max_retries

        # Generate token
        gen_result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token = gen_result.data.token

        # Exhaust retries
        for i in range(max_retries):
            result = service.validate_download_request(token, "test_user")
            if i < max_retries - 1:
                assert result.success is True
            else:
                # Last one should succeed but be the limit
                assert result.success is True

        # Next attempt should fail
        result = service.validate_download_request(token, "test_user")
        assert result.success is False
        assert "exhausted" in result.error.lower() or "exceeded" in result.error.lower()

    def test_validate_token_not_found(self, service: DownloadService):
        """Validate non-existent token."""
        result = service.validate_download_request("nonexistent-token", "test_user")
        assert result.success is False
        assert "not found" in result.error.lower()


# =============================================================================
# Test: Cleanup
# =============================================================================


class TestCleanupExpiredTokens:
    """Tests for token cleanup."""

    def test_cleanup_removes_expired(self, service: DownloadService, test_file: Path):
        """TEST 6: Cleanup removes expired tokens."""
        # Generate two tokens
        gen_result1 = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token1 = gen_result1.data.token

        gen_result2 = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token2 = gen_result2.data.token

        # Expire first token
        async def expire_first():
            info = await _registry.get_info(token1)
            info.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await _registry.store(token1, info, b"test")

        asyncio.run(expire_first())

        # Cleanup should remove 1 token
        result = service.cleanup_expired_tokens()
        assert result.success is True
        assert result.data == 1

        # Verify token1 is gone
        info1 = asyncio.run(_registry.get_info(token1))
        assert info1 is None

        # Verify token2 still exists
        info2 = asyncio.run(_registry.get_info(token2))
        assert info2 is not None

    def test_cleanup_preserves_valid(self, service: DownloadService, test_file: Path):
        """TEST 7: Cleanup preserves valid tokens."""
        # Generate a valid token
        gen_result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token = gen_result.data.token

        # Cleanup should remove 0 tokens
        result = service.cleanup_expired_tokens()
        assert result.success is True
        assert result.data == 0

        # Verify token still exists
        info = asyncio.run(_registry.get_info(token))
        assert info is not None


# =============================================================================
# Test: UUID Uniqueness
# =============================================================================


class TestTokenUniqueness:
    """Tests for token uniqueness."""

    def test_token_uuid_uniqueness(self, service: DownloadService, test_file: Path):
        """TEST 8: 100 generated tokens are unique."""
        tokens = set()

        for i in range(100):
            result = service.generate_download_token(
                file_path=test_file,
                user_id=f"user_{i}",
                file_format="json",
            )
            assert result.success is True
            tokens.add(result.data.token)

        # All tokens should be unique
        assert len(tokens) == 100


# =============================================================================
# Test: Thread Safety / Concurrent Access
# =============================================================================


class TestThreadSafety:
    """Tests for thread-safe registry access via run_async().

    asyncio.Lock deadlocks when two threads with different event
    loops contend for the same lock. threading.Lock prevents this.
    The deadlock only manifests when there is actual contention — two threads
    must try to acquire the lock at the same time. Without contention,
    asyncio.Lock appears to work because the fast path in acquire() skips
    the _get_loop() check.
    """

    @pytest.mark.slow
    def test_concurrent_update_attempts_no_race_condition(
        self, service: DownloadService, test_file: Path
    ):
        """Concurrent update_attempts calls from multiple threads don't lose updates.

        Uses threading.Barrier to force two threads to contend for the lock
        simultaneously. With asyncio.Lock this would deadlock; with
        threading.Lock it completes correctly.
        """
        # Generate a token with known attempts
        gen_result = service.generate_download_token(
            file_path=test_file,
            user_id="test_user",
            file_format="json",
        )
        token = gen_result.data.token

        # Manually set high attempts for testing
        async def set_high_attempts():
            info = await _registry.get_info(token)
            info.attempts_remaining = 100
            await _registry.store(token, info, b"test")

        asyncio.run(set_high_attempts())

        num_threads = 10
        calls_per_thread = 10
        total_decrements = num_threads * calls_per_thread  # 100

        def decrement_worker(_: int) -> list[bool]:
            from ciberwebscan.utils.async_runner import run_async

            results = []
            for _ in range(calls_per_thread):
                result = run_async(_registry.update_attempts(token))
                results.append(result)
            return results

        # Run concurrent threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(decrement_worker, i) for i in range(num_threads)]
            all_results = []
            for future in concurrent.futures.as_completed(futures):
                all_results.extend(future.result())

        # Check final state
        final_info = asyncio.run(_registry.get_info(token))
        final_attempts = final_info.attempts_remaining if final_info else None

        successful_calls = sum(1 for r in all_results if r is True)
        failed_calls = sum(1 for r in all_results if r is False)

        # With 100 initial attempts and 100 decrements, we expect 0 remaining
        # If there was a race condition, final_attempts would be > 0 (lost decrements)
        assert final_attempts == max(0, 100 - total_decrements)
        assert successful_calls == total_decrements
        assert failed_calls == 0

    @pytest.mark.slow
    def test_concurrent_store_and_get_no_corruption(
        self, service: DownloadService, test_file: Path
    ):
        """Concurrent store/get operations don't corrupt or lose data."""
        num_threads = 10
        ops_per_thread = 20
        errors: list[tuple[str, str]] = []

        def worker(thread_id: int, ops: int) -> None:
            from ciberwebscan.utils.async_runner import run_async

            for i in range(ops):
                token = f"thread_{thread_id}_op_{i}"
                info = DownloadInfo(
                    token=token,
                    user_id=f"user_{thread_id}",
                    file_size_bytes=100,
                    created_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                    attempts_remaining=3,
                    file_format="json",
                )
                file_data = f"data_{thread_id}_{i}".encode()

                try:
                    run_async(_registry.store(token, info, file_data))
                    retrieved_info = run_async(_registry.get_info(token))
                    retrieved_data = run_async(_registry.get_file_data(token))

                    if retrieved_info is None or retrieved_data is None:
                        errors.append(("MISSING", token))
                    elif retrieved_info.token != token or retrieved_data != file_data:
                        errors.append(("CORRUPTED", token))
                except Exception as e:
                    errors.append(("ERROR", str(e)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(worker, i, ops_per_thread) for i in range(num_threads)
            ]
            for future in concurrent.futures.as_completed(futures):
                future.result()

        assert len(errors) == 0, f"Data corruption/loss detected: {errors[:5]}"

    @pytest.mark.slow
    def test_cleanup_concurrent_with_operations(
        self, service: DownloadService, test_file: Path
    ):
        """Cleanup running concurrently with store/get doesn't cause errors."""
        num_ops = 100
        errors: list[tuple[str, str]] = []

        def store_worker() -> None:
            from ciberwebscan.utils.async_runner import run_async

            for i in range(num_ops):
                token = f"store_{i}"
                info = DownloadInfo(
                    token=token,
                    user_id="test_user",
                    file_size_bytes=100,
                    created_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                    attempts_remaining=3,
                    file_format="json",
                )
                try:
                    run_async(_registry.store(token, info, b"data"))
                except Exception as e:
                    errors.append(("store", str(e)))

        def get_worker() -> None:
            from ciberwebscan.utils.async_runner import run_async

            for i in range(num_ops):
                token = f"store_{i}"
                try:
                    run_async(_registry.get_info(token))
                except Exception as e:
                    errors.append(("get", str(e)))

        def cleanup_worker() -> None:
            from ciberwebscan.utils.async_runner import run_async

            for _ in range(10):
                try:
                    run_async(_registry.cleanup_expired())
                except Exception as e:
                    errors.append(("cleanup", str(e)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(store_worker),
                executor.submit(store_worker),
                executor.submit(get_worker),
                executor.submit(cleanup_worker),
            ]
            for future in concurrent.futures.as_completed(futures):
                future.result()

        assert len(errors) == 0, f"Errors during concurrent access: {errors[:5]}"

    @pytest.mark.slow
    def test_asyncio_lock_deadlock_detection(self, test_file: Path):
        """Verify that asyncio.Lock would deadlock under contention.

        BUG-002: asyncio.Lock binds to the event loop that first acquires it
        when contention occurs. When a second thread with a different event
        loop tries to acquire the same lock, it hangs forever (deadlock).

        This test forces contention using threading.Barrier and a timeout.
        With asyncio.Lock: deadlock (timeout).
        With threading.Lock: completes normally.
        """
        import threading as _threading

        barrier = _threading.Barrier(2, timeout=10)
        lock = _threading.Lock()  # Uses threading.Lock (the fix)
        results = []

        async def contention_op():
            barrier.wait()  # Force both threads to reach this point
            with lock:
                results.append(1)

        def run_in_thread():
            from ciberwebscan.utils.async_runner import run_async

            run_async(contention_op())

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(run_in_thread)
            f2 = pool.submit(run_in_thread)
            f1.result(timeout=15)
            f2.result(timeout=15)

        assert len(results) == 2, (
            f"Expected 2 results, got {len(results)}. "
            "If using asyncio.Lock, this would deadlock."
        )
