"""
Helper functions for download token generation in routes.

Provides utility functions to enrich service results with download tokens
and generate correct download URLs via FastAPI's request.url_for().
"""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar
from urllib.parse import urlparse

from fastapi import Request

from ciberwebscan.config.loader import get_config
from ciberwebscan.export import EXPORT_FORMATS
from ciberwebscan.services.base import ServiceResult
from ciberwebscan.services.download_service import DownloadService

T = TypeVar("T")


def _detect_export_format(export_format: str | None, export_path: Path) -> str:
    """Resolve the export format for download metadata.

    Preference order: the format reported by the service, then the export
    file extension, then ``json``. Unknown values are discarded so they
    can never surface in download metadata.

    Args:
        export_format: Format reported by the service result, if any.
        export_path: Path of the exported file.

    Returns:
        One of ``EXPORT_FORMATS``.
    """
    if export_format is not None and export_format in EXPORT_FORMATS:
        return export_format
    suffix = export_path.suffix.removeprefix(".").lower()
    if suffix in EXPORT_FORMATS:
        return suffix
    return "json"


def enrich_response_with_token(
    result: ServiceResult[T],
    user_id: str,
    download_service: DownloadService,
    request: Request,
) -> tuple[T | None, str | None, str | None]:
    """
    Intercept export_path from service result and generate download token.

    Safely extracts the file_path from the result and generates a download token.
    If no export_path exists or token generation fails, logs error but doesn't fail.
    Generates the download URL using request.url_for() to ensure consistency
    with the actual registered route.

    Args:
        result: ServiceResult from analysis/attack/scrape service
        user_id: ID of user who made the request
        download_service: DownloadService instance
        request: FastAPI Request object for URL generation

    Returns:
        Tuple of (data, download_token, download_url) where token and url
        are None if not generated
    """
    # If no export_path, return data without token
    if result.export_path is None:
        return result.data, None, None

    # Downloads disabled is an expected state, not a failure: skip the
    # service call so the (already gated) export does not emit a warning
    # per request. The service remains the authoritative admission gate.
    if not get_config().download.enabled:
        download_service.logger.debug(
            "Download token skipped: downloads are disabled (download.enabled=false)"
        )
        return result.data, None, None

    # Generate token from the exported file with the real export format
    # (previously hardcoded to "json", which mislabeled every download).
    token_result = download_service.generate_download_token(
        file_path=result.export_path,
        user_id=user_id,
        file_format=_detect_export_format(result.export_format, result.export_path),
    )

    # If token generation failed, log but don't error
    if not token_result.success or token_result.data is None:
        download_service.logger.warning(
            f"Failed to generate download token: {token_result.error}"
        )
        return result.data, None, None

    token = token_result.data.token
    download_url = urlparse(str(request.url_for("download_file", token=token))).path

    return result.data, token, download_url
