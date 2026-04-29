"""
Tests for DownloadService class.
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ciberwebscan.api.models.responses import DownloadTokenResponse
from ciberwebscan.config.loader import get_config
from ciberwebscan.services.download_service import DownloadService, _registry

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def service() -> DownloadService:
    """Create a test service instance."""
    return DownloadService()


@pytest.fixture
def test_file() -> Path:
    """Create a temporary test file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        f.write('{"test": "data"}')
        return Path(f.name)


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear the registry before and after each test."""
    asyncio.run(_registry.cleanup_expired())
    yield
    asyncio.run(_registry.cleanup_expired())


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
        assert result.data.download_url == f"/api/v1/download/{result.data.token}"
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
