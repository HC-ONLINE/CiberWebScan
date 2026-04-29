"""
Download endpoint for file downloads.

Provides streaming download endpoint with token-based authentication
and rate limiting.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.config.loader import get_config
from ciberwebscan.services.download_service import DownloadService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/download", tags=["download"])

# Service instance
_download_service = DownloadService()


def _get_download_service() -> DownloadService:
    """Get download service instance."""
    return _download_service


@router.get(
    "/{token}",
    summary="Download exported results",
    description="Download previously exported analysis/attack/scrape results using a time-limited token.",
    responses={
        200: {"description": "File downloaded successfully"},
        400: {"description": "Invalid token"},
        401: {"description": "Unauthorized - different user or max retries exceeded"},
        404: {"description": "Token not found"},
        410: {"description": "Token expired"},
        503: {"description": "Download service unavailable"},
    },
)
async def download_file(
    token: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    download_service: Annotated[DownloadService, Depends(_get_download_service)],
) -> StreamingResponse:
    """
    Download file using a download token.

    The token is obtained from POST endpoints (analyze, attack, scrape).
    Tokens expire after a configured time period and have a limited number of retry attempts.

    Args:
        token: Download token from response
        user: Authenticated user from API key
        download_service: Download service instance (injected via Depends)

    Returns:
        StreamingResponse with file data

    Raises:
        HTTPException: If token is invalid, expired, or user unauthorized
    """
    config = get_config()

    # Check if download is enabled
    if not config.download.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Download service is disabled",
        )

    # Validate token
    validation_result = download_service.validate_download_request(
        token=token,
        user_id=user.identifier,
    )

    if not validation_result.success:
        error_msg = validation_result.error or "Invalid token"

        # Determine appropriate HTTP status code
        if "expired" in error_msg.lower():
            status_code = status.HTTP_410_GONE
        elif "unauthorized" in error_msg.lower():
            status_code = status.HTTP_401_UNAUTHORIZED
        elif "attempts" in error_msg.lower():
            status_code = status.HTTP_429_TOO_MANY_REQUESTS
        else:
            status_code = status.HTTP_400_BAD_REQUEST

        logger.warning(f"Download validation failed for {user.identifier}: {error_msg}")
        raise HTTPException(status_code=status_code, detail=error_msg)

    # Get file stream
    stream_result = download_service.get_file_stream(token=token)
    if not stream_result.success:
        logger.error(f"Failed to get file stream: {stream_result.error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve file",
        )

    # Prepare headers
    headers = {
        "Content-Disposition": "attachment; filename=export.json",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }

    logger.info(f"Streaming download for token {token} to user {user.identifier}")

    # Get file stream and validate data is not None
    if stream_result.data is None:
        logger.error("Stream result data is None despite success status")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve file stream",
        )

    # Capture stream data to ensure it's not None for type checker
    file_chunks = stream_result.data

    # Wrapper generator that cleans up token after streaming completes
    def stream_and_cleanup():
        """Stream file data and cleanup token after completion."""
        try:
            yield from file_chunks
        finally:
            # Clean up token after successful stream
            cleanup_result = download_service.delete_token(token)
            if cleanup_result.success:
                logger.info(f"Token cleaned up after download: {token}")
            else:
                logger.warning(f"Failed to cleanup token: {token}")

    return StreamingResponse(
        stream_and_cleanup(),
        media_type="application/octet-stream",
        headers=headers,
    )
