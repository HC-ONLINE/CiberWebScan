"""
Download endpoint for file downloads.

Provides streaming download endpoint with token-based authentication
and rate limiting.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.config.loader import get_config
from ciberwebscan.export import EXPORT_FORMATS
from ciberwebscan.services.download_service import DownloadService
from ciberwebscan.utils.logging import mask_identifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/download", tags=["download"])


def _content_disposition(file_format: str | None) -> str:
    """Build the Content-Disposition header for an export format.

    Only formats in ``EXPORT_FORMATS`` reach the header, so a
    tampered registry value can never inject header content; anything
    else falls back to ``json``.

    Args:
        file_format: Format stored in the token metadata, if any.

    Returns:
        The Content-Disposition value with a format-specific filename.
    """
    extension = file_format if file_format in EXPORT_FORMATS else "json"
    return f'attachment; filename="export.{extension}"'


# Service instance
_download_service = DownloadService()


def _get_download_service() -> DownloadService:
    """Get download service instance."""
    return _download_service


class _AttemptReservation:
    """Couple the attempt consumed by validation to at most one refund.

    The registry enforces the complementary guarantees (the token must
    still exist and the counter must stay within ``download.max_retries``);
    this helper only ensures a single request cannot refund its own
    reservation twice, so refunds can never outnumber reservations.

    Not thread-safe on its own: one-shot semantics rely on the call sites
    being mutually exclusive per request (the handler refunds before the
    ``StreamingResponse`` exists; the generator refunds only after it was
    returned), never both for the same reservation.
    """

    def __init__(self, download_service: DownloadService, token: str) -> None:
        self._download_service = download_service
        self._token = token
        self._refunded = False

    def refund_once(self) -> bool:
        """Refund the reserved attempt at most once for this request.

        The claimed flag is set before calling the service so an unexpected
        error can never arm a second refund.

        Returns:
            True when this call restored an attempt, False when the
            reservation was already refunded or the registry refused it.
        """
        if self._refunded:
            return False
        self._refunded = True
        return self._download_service.restore_attempt(self._token).success


def _stream_and_cleanup(
    download_service: DownloadService,
    token: str,
    file_chunks: Iterator[bytes],
    reservation: _AttemptReservation,
) -> Iterator[bytes]:
    """Stream file data and finalize the token according to the outcome.

    - Completed delivery: the token is deleted (one-shot download).
    - Server exception mid-stream: the reserved attempt is refunded once
      and the token is kept so the user can retry.
    - ``GeneratorExit`` (client disconnect or generator close): the token
      is kept and the attempt stays consumed — no refund.

    ``GeneratorExit`` is only delivered when the generator is closed or
    garbage-collected, so the disconnect log is best-effort: the attempt
    and token policy never depends on it (the attempt is consumed at
    validation time and this branch changes no state).
    """
    # Any other BaseException (CancelledError, KeyboardInterrupt, SystemExit)
    # propagates without matching a handler below: no refund, no delete — the
    # conservative outcome is the same as a disconnect (attempt consumed,
    # token kept until expiry), so a stray cancellation can never inflate the
    # counter nor destroy a reusable token.
    try:
        yield from file_chunks
    except GeneratorExit:
        # Client disconnect: keep the token (retry possible) and keep the
        # consumed attempt (bounds abort/retry loops). Re-raising is
        # mandatory once GeneratorExit has been caught.
        logger.info(f"Client disconnected during download: {token}")
        raise
    except Exception:
        # Server-side failure mid-delivery: refund the reservation once
        # and keep the token. The error propagates to the ASGI server.
        if reservation.refund_once():
            logger.error(f"Stream failed for token {token}; attempt refunded")
        else:
            logger.error(
                f"Stream failed for token {token}; refund not applied "
                "(already refunded or refused by registry)"
            )
        raise
    else:
        # Success is the only branch that deletes the token.
        cleanup_result = download_service.delete_token(token)
        if cleanup_result.success:
            logger.info(f"Token cleaned up after download: {token}")
        else:
            logger.warning(f"Failed to cleanup token: {token}")


@router.get(
    "/{token}",
    summary="Download exported results",
    description=(
        "Download previously exported analysis/attack/scrape results using a "
        "time-limited token. Every request that passes token validation "
        "consumes one of the token's retry attempts; a server-side failure "
        "returns the attempt, while a completed download deletes the token. "
        "A client disconnect keeps the token until it expires and does not "
        "return the attempt."
    ),
    responses={
        200: {"description": "File downloaded successfully"},
        400: {"description": "Invalid token"},
        401: {"description": "Unauthorized - token belongs to a different user"},
        404: {"description": "Token not found"},
        410: {"description": "Token expired"},
        429: {"description": "Too many retry attempts"},
        500: {
            "description": (
                "Internal error while opening or streaming the export file "
                "(the consumed attempt is returned)"
            )
        },
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
    Tokens expire after a configured time period and have a limited number
    of retry attempts. Validation consumes one attempt; server-side
    failures return it via a one-shot reservation, while a completed
    download deletes the token.

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

    # Log-safe caller identity: never write raw API key material to logs.
    log_user = mask_identifier(user.identifier)

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

        logger.warning(f"Download validation failed for {log_user}: {error_msg}")
        raise HTTPException(status_code=status_code, detail=error_msg)

    # The validation above consumed one attempt: pair that reservation with
    # a one-shot refund guard used on the server-side failure paths below.
    reservation = _AttemptReservation(download_service, token)

    # Get file stream
    stream_result = download_service.get_file_stream(token=token)
    if not stream_result.success:
        reservation.refund_once()
        logger.error(f"Failed to get file stream: {stream_result.error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve file",
        )

    # Validate data is not None before announcing the stream
    if stream_result.data is None:
        reservation.refund_once()
        logger.error("Stream result data is None despite success status")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve file stream",
        )

    # Token metadata: the stored export format drives the download filename
    info_result = download_service.get_info(token=token)
    if not info_result.success or info_result.data is None:
        reservation.refund_once()
        logger.error(f"Failed to get download metadata: {info_result.error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve file metadata",
        )

    # Prepare headers
    headers = {
        "Content-Disposition": _content_disposition(info_result.data.file_format),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }

    logger.info(f"Streaming download for token {token} to user {log_user}")

    # Capture stream data to ensure it's not None for type checker
    file_chunks = stream_result.data

    return StreamingResponse(
        _stream_and_cleanup(download_service, token, file_chunks, reservation),
        media_type="application/octet-stream",
        headers=headers,
    )
