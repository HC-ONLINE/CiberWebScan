"""
Security analysis endpoints for CiberWebScan API.
"""

from __future__ import annotations

import logging
from functools import partial
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError

from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.api.concurrency import run_scan
from ciberwebscan.api.helpers.download_helper import enrich_response_with_token
from ciberwebscan.api.models.requests import AnalyzeRequest
from ciberwebscan.api.models.responses import APIResponse
from ciberwebscan.export.models import AnalysisReport
from ciberwebscan.services.analyze_service import AnalyzeOptions, AnalyzeService
from ciberwebscan.services.download_service import DownloadService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/analyze",
    response_model=APIResponse[AnalysisReport],
    responses={
        429: {
            "description": (
                "Too many concurrent scans (api.max_concurrent_scans); "
                "retry after the advertised Retry-After seconds"
            )
        },
        504: {
            "description": (
                "Scan exceeded api.scan_timeout_seconds; the blocking work "
                "may still be running server-side"
            )
        },
    },
)
async def analyze_url(
    request: AnalyzeRequest,
    http_request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[AnalysisReport]:
    """
    Perform security analysis on a URL.
    Supports SSL analysis, technology fingerprinting, header analysis, and CVE lookup.

    Runs under the API's scan admission control: at most
    ``api.max_concurrent_scans`` scans execute at once per process; excess
    requests receive 429 instead of queueing indefinitely.
    """
    return await run_scan(partial(_analyze_sync, request, http_request, user))


def _analyze_sync(
    request: AnalyzeRequest,
    http_request: Request,
    user: AuthenticatedUser,
) -> APIResponse[AnalysisReport]:
    """Blocking analysis implementation (runs in a worker thread)."""
    try:
        # Convert request to service options
        options = AnalyzeOptions(
            url=str(request.url),
            # Analysis types
            ssl=request.ssl,
            fingerprint=request.fingerprint,
            analyze_headers=request.analyze_headers,
            cve=request.cve,
            ssl_verify=request.ssl_verify,
            timeout=request.timeout,
            ssl_timeout=request.ssl_timeout,
            deep_scan=request.deep_scan,
            cve_sources=request.cve_sources,
            cve_limit=request.cve_limit,
            cve_severity=request.cve_severity,
            headers=request.headers,
            cookies=request.cookies,
            proxy=request.proxy,
            user_agent=request.user_agent,
            check_robots=request.check_robots,
            enrich_exploits=request.enrich_exploits,
            export=request.export,
            export_format=request.export_format,
        )

        # Execute analysis
        service = AnalyzeService()
        result = service.analyze(options)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error or "Analysis failed",
            )

        # Enrich response with download token
        download_service = DownloadService()
        data, download_token, download_url = enrich_response_with_token(
            result, user.identifier, download_service, http_request
        )

        return APIResponse[AnalysisReport](
            success=True,
            data=data,
            download_token=download_token,
            download_url=download_url,
        )

    except ValidationError as e:
        logger.warning(f"Validation error in analyze request: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid request: {e}"
        ) from e
    except Exception as e:
        logger.error(f"Error analyzing URL {request.url}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        ) from e
