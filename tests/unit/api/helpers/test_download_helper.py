"""
Unit tests for download token enrichment in routes.

Covers export-format detection when generating download metadata: the
format reported by the service wins, the export file extension is the
fallback, and unknown values resolve to "json" instead of leaking into
download metadata.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ciberwebscan.api.helpers.download_helper import (
    _detect_export_format,
    enrich_response_with_token,
)
from ciberwebscan.api.models.responses import DownloadTokenResponse
from ciberwebscan.config.models import AppConfig
from ciberwebscan.services.base import ServiceResult

pytestmark = pytest.mark.unit


# =============================================================================
# Test: Format detection
# =============================================================================


class TestDetectExportFormat:
    """Preference order: service format → file extension → json."""

    @pytest.mark.parametrize(
        ("export_format", "path", "expected"),
        [
            ("csv", "out.json", "csv"),
            ("jsonl", "out.csv", "jsonl"),
            ("html", "out.txt", "html"),
            (None, "out.csv", "csv"),
            (None, "out.jsonl", "jsonl"),
            (None, "out.HTML", "html"),
            ("xml", "out.csv", "csv"),
            ('csv"\r\nX: 1', "out.csv", "csv"),
            ("xml", "out.txt", "json"),
            (None, "out", "json"),
            (None, "out.xml", "json"),
            ("", "out", "json"),
        ],
    )
    def test_detection(self, export_format: str | None, path: str, expected: str):
        assert _detect_export_format(export_format, Path(path)) == expected


# =============================================================================
# Test: Token enrichment
# =============================================================================


class TestEnrichResponseWithToken:
    """The generated token stores the detected export format."""

    def _make_request(self) -> Mock:
        request = Mock()
        request.url_for.return_value = "http://testserver/api/download/tok-1"
        return request

    def _make_service(self) -> Mock:
        service = Mock()
        service.generate_download_token.return_value = ServiceResult.ok(
            DownloadTokenResponse(token="tok-1", expires_at=datetime.now(timezone.utc))
        )
        return service

    def test_token_stores_service_reported_format(self):
        result: ServiceResult[dict] = ServiceResult.ok(
            data={"ok": True},
            export_path=Path("exports/report.csv"),
            export_format="csv",
        )

        service = self._make_service()
        _, token, url = enrich_response_with_token(
            result, "user-1", service, self._make_request()
        )

        assert token == "tok-1"
        assert url == "/api/download/tok-1"
        service.generate_download_token.assert_called_once_with(
            file_path=Path("exports/report.csv"),
            user_id="user-1",
            file_format="csv",
        )

    def test_token_falls_back_to_extension_without_service_format(self):
        result: ServiceResult[dict] = ServiceResult.ok(
            data={"ok": True}, export_path=Path("exports/report.jsonl")
        )

        service = self._make_service()
        enrich_response_with_token(result, "user-1", service, self._make_request())

        assert (
            service.generate_download_token.call_args.kwargs["file_format"] == "jsonl"
        )

    def test_no_export_path_returns_no_token(self):
        result: ServiceResult[dict] = ServiceResult.ok(data={"ok": True})

        service = self._make_service()
        data, token, url = enrich_response_with_token(
            result, "user-1", service, self._make_request()
        )

        assert data == {"ok": True}
        assert token is None
        assert url is None
        service.generate_download_token.assert_not_called()

    def test_disabled_downloads_skip_token_generation(self):
        """download.enabled=false short-circuits without warning per export.

        The service is the authoritative gate; the helper skips the call so
        an expected "disabled" state does not emit a warning on every export.
        """
        result: ServiceResult[dict] = ServiceResult.ok(
            data={"ok": True}, export_path=Path("exports/report.csv")
        )

        service = self._make_service()
        config = AppConfig()
        config.download.enabled = False

        with patch(
            "ciberwebscan.api.helpers.download_helper.get_config",
            return_value=config,
        ):
            data, token, url = enrich_response_with_token(
                result, "user-1", service, self._make_request()
            )

        assert data == {"ok": True}
        assert token is None
        assert url is None
        service.generate_download_token.assert_not_called()
