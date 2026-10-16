"""
Unit tests for the download route helpers.

Covers the one-shot attempt reservation and the streaming finalization
branches: success deletes the token, a server exception refunds the
reservation once, and a disconnect (``GeneratorExit``) keeps the token
with the attempt still consumed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from ciberwebscan.api.routes.download import (
    _AttemptReservation,
    _content_disposition,
    _stream_and_cleanup,
)
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
def reset_registry():
    """Wipe the shared registry before and after each test.

    ``cleanup_expired()`` only removes expired tokens, which would let
    fresh tokens leak between tests in the same session; this fixture
    removes every entry under the registry lock so each test starts from
    a genuinely empty registry. The registry lock is a plain
    ``threading.Lock``, so the wipe is synchronous.
    """

    def _wipe() -> None:
        with _registry._lock:  # noqa: SLF001 - test-only introspection
            _registry._tokens.clear()  # noqa: SLF001
            _registry._file_data.clear()  # noqa: SLF001

    _wipe()
    yield
    _wipe()


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


def _generate_token(service: DownloadService, test_file: Path) -> str:
    gen_result = service.generate_download_token(
        file_path=test_file,
        user_id="test_user",
        file_format="json",
    )
    assert gen_result.success is True
    return gen_result.data.token


def _attempts(token: str) -> int | None:
    info = asyncio.run(_registry.get_info(token))
    return info.attempts_remaining if info else None


# =============================================================================
# Test: One-shot reservation
# =============================================================================


class TestAttemptReservation:
    """The refund guard couples a reservation to at most one refund."""

    def test_refund_once_restores_only_once(
        self, service: DownloadService, test_file: Path
    ):
        """Scenario 9: a second refund_once() call cannot restore again."""
        max_retries = get_config().download.max_retries
        token = _generate_token(service, test_file)
        reservation = _AttemptReservation(service, token)

        assert service.validate_download_request(token, "test_user").success is True
        assert _attempts(token) == max_retries - 1

        assert reservation.refund_once() is True
        assert _attempts(token) == max_retries

        # Second call is a no-op even though the token still exists.
        assert reservation.refund_once() is False
        assert _attempts(token) == max_retries

    def test_refund_once_without_consumed_reservation_is_refused(
        self, service: DownloadService, test_file: Path
    ):
        """An unpaired refund cannot inflate the counter past the maximum."""
        max_retries = get_config().download.max_retries
        token = _generate_token(service, test_file)
        reservation = _AttemptReservation(service, token)

        assert reservation.refund_once() is False
        assert _attempts(token) == max_retries


# =============================================================================
# Test: Content-Disposition header
# =============================================================================


class TestContentDisposition:
    """The download filename always reflects a supported export format."""

    @pytest.mark.parametrize(
        ("file_format", "expected"),
        [
            ("json", 'attachment; filename="export.json"'),
            ("jsonl", 'attachment; filename="export.jsonl"'),
            ("csv", 'attachment; filename="export.csv"'),
            ("html", 'attachment; filename="export.html"'),
        ],
    )
    def test_supported_formats_produce_matching_filename(
        self, file_format: str, expected: str
    ):
        assert _content_disposition(file_format) == expected

    @pytest.mark.parametrize(
        "file_format",
        [None, "", "xml", "js", "json\r\nX-Injected: 1", 'csv"; evil=y'],
    )
    def test_unsupported_values_fall_back_to_json(self, file_format: str | None):
        """Registry values outside the allowlist never reach the header."""
        assert _content_disposition(file_format) == 'attachment; filename="export.json"'


# =============================================================================
# Test: Streaming finalization
# =============================================================================


class TestStreamAndCleanup:
    """Finalization branches of the download streaming generator."""

    def test_completed_stream_deletes_token(
        self, service: DownloadService, test_file: Path
    ):
        """Scenario 5 (unit): a full delivery removes the token."""
        expected = test_file.read_bytes()
        token = _generate_token(service, test_file)
        assert service.validate_download_request(token, "test_user").success is True

        stream_result = service.get_file_stream(token=token)
        assert stream_result.success is True and stream_result.data is not None
        reservation = _AttemptReservation(service, token)

        payload = b"".join(
            _stream_and_cleanup(service, token, stream_result.data, reservation)
        )

        assert payload == expected
        assert asyncio.run(_registry.get_info(token)) is None

    def test_server_exception_mid_stream_refunds_once_and_keeps_token(
        self, service: DownloadService, test_file: Path
    ):
        """Scenario 3: mid-stream failure refunds once and keeps the token."""
        max_retries = get_config().download.max_retries
        token = _generate_token(service, test_file)
        assert service.validate_download_request(token, "test_user").success is True
        reservation = _AttemptReservation(service, token)

        def failing_chunks() -> Iterator[bytes]:
            yield b"partial-content"
            raise RuntimeError("read failure")

        generator = _stream_and_cleanup(service, token, failing_chunks(), reservation)
        assert next(generator) == b"partial-content"
        with pytest.raises(RuntimeError, match="read failure"):
            next(generator)

        # Token kept; the attempt was refunded exactly once.
        assert asyncio.run(_registry.get_info(token)) is not None
        assert _attempts(token) == max_retries
        # Duplicated error handling cannot refund a second time.
        assert reservation.refund_once() is False
        assert _attempts(token) == max_retries

    def test_generator_close_keeps_token_and_consumes_attempt(
        self, service: DownloadService, test_file: Path
    ):
        """Scenario 4: a disconnect keeps the token and consumes the attempt.

        ``gen.close()`` delivers ``GeneratorExit`` at the suspended yield —
        the same deterministic mechanism Python finalization uses when a
        suspended generator is collected. No sleeps, no forced GC.
        """
        max_retries = get_config().download.max_retries
        expected = test_file.read_bytes()
        token = _generate_token(service, test_file)
        assert service.validate_download_request(token, "test_user").success is True

        stream_result = service.get_file_stream(token=token)
        assert stream_result.success is True and stream_result.data is not None
        reservation = _AttemptReservation(service, token)

        generator = _stream_and_cleanup(service, token, stream_result.data, reservation)
        first_chunk = next(generator)
        assert first_chunk == expected[: len(first_chunk)]
        generator.close()  # client disconnect: GeneratorExit

        # Token kept for a retry; the attempt stays consumed (no refund).
        assert asyncio.run(_registry.get_info(token)) is not None
        assert _attempts(token) == max_retries - 1
