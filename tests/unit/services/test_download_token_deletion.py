"""Test token deletion functionality after download."""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from ciberwebscan.services.download_service import DownloadService, _registry


class TestTokenDeletion:
    """Test token deletion after successful download."""

    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            f.write(b'{"test": "data"}')
            temp_path = f.name
        yield temp_path
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def download_service(self):
        """Create download service."""
        return DownloadService()

    @pytest.fixture(autouse=True)
    def clear_registry(self):
        """Clear the registry before and after each test."""
        asyncio.run(_registry.cleanup_expired())
        yield
        asyncio.run(_registry.cleanup_expired())

    def test_delete_token_removes_token(self, download_service, temp_file):
        """Test that delete_token removes token from registry."""
        # Generate a token
        result = download_service.generate_download_token(
            file_path=temp_file, user_id="user123", file_format="json"
        )
        assert result.success
        token = result.data.token

        # Verify token exists
        validate_result = download_service.validate_download_request(
            token=token, user_id="user123"
        )
        assert validate_result.success

        # Delete token
        delete_result = download_service.delete_token(token)
        assert delete_result.success

        # Verify token is gone
        validate_after = download_service.validate_download_request(
            token=token, user_id="user123"
        )
        assert not validate_after.success
        assert "not found" in validate_after.error.lower()

    def test_delete_nonexistent_token_returns_error(self, download_service):
        """Test that deleting non-existent token returns error."""
        result = download_service.delete_token("nonexistent-token")
        assert not result.success
        assert "not found" in result.error.lower()

    def test_token_deleted_prevents_retry(self, download_service, temp_file):
        """Test that deleted token cannot be used for retries."""
        # Generate token
        result = download_service.generate_download_token(
            file_path=temp_file, user_id="user123", file_format="json"
        )
        assert result.success
        token = result.data.token

        # Delete token immediately
        delete_result = download_service.delete_token(token)
        assert delete_result.success

        # Try to use token - should fail
        validate_result = download_service.validate_download_request(
            token=token, user_id="user123"
        )
        assert not validate_result.success

    def test_multiple_tokens_independent_deletion(self, download_service, temp_file):
        """Test that deleting one token doesn't affect others."""
        # Generate two tokens
        result1 = download_service.generate_download_token(
            file_path=temp_file, user_id="user123", file_format="json"
        )
        result2 = download_service.generate_download_token(
            file_path=temp_file, user_id="user456", file_format="json"
        )
        assert result1.success
        assert result2.success

        token1 = result1.data.token
        token2 = result2.data.token

        # Delete first token
        delete_result = download_service.delete_token(token1)
        assert delete_result.success

        # Verify first token is gone
        validate1 = download_service.validate_download_request(
            token=token1, user_id="user123"
        )
        assert not validate1.success

        # Verify second token still exists
        validate2 = download_service.validate_download_request(
            token=token2, user_id="user456"
        )
        assert validate2.success

    def test_delete_token_idempotent(self, download_service, temp_file):
        """Test that deleting already deleted token returns appropriate response."""
        # Generate and delete token
        result = download_service.generate_download_token(
            file_path=temp_file, user_id="user123", file_format="json"
        )
        token = result.data.token

        delete1 = download_service.delete_token(token)
        assert delete1.success

        # Try to delete again
        delete2 = download_service.delete_token(token)
        assert not delete2.success  # Should fail as token doesn't exist
