"""
Helper functions for download token generation in routes.

Provides utility functions to enrich service results with download tokens.
"""

from __future__ import annotations

from typing import TypeVar

from ciberwebscan.services.base import ServiceResult
from ciberwebscan.services.download_service import DownloadService

T = TypeVar("T")


def enrich_response_with_token(
    result: ServiceResult[T],
    user_id: str,
    download_service: DownloadService,
) -> tuple[T | None, str | None]:
    """
    Intercept export_path from service result and generate download token.

    Safely extracts the file_path from the result and generates a download token.
    If no export_path exists or token generation fails, logs error but doesn't fail.

    Args:
        result: ServiceResult from analysis/attack/scrape service
        user_id: ID of user who made the request
        download_service: DownloadService instance

    Returns:
        Tuple of (data, download_token) where token is None if not generated
    """
    # If no export_path, return data without token
    if result.export_path is None:
        return result.data, None

    # Generate token from the exported file
    token_result = download_service.generate_download_token(
        file_path=result.export_path,
        user_id=user_id,
        file_format="json",  # Default format, could be detected from path extension
    )

    # If token generation failed, log but don't error
    if not token_result.success or token_result.data is None:
        download_service.logger.warning(
            f"Failed to generate download token: {token_result.error}"
        )
        return result.data, None

    return result.data, token_result.data.token
