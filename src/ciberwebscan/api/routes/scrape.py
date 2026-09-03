"""
Scraping endpoints for CiberWebScan API.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated, Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError

from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.api.helpers.download_helper import enrich_response_with_token
from ciberwebscan.api.models.requests import ScrapeBatchRequest, ScrapeRequest
from ciberwebscan.api.models.responses import (
    APIResponse,
    ScrapeBatchResultResponse,
)
from ciberwebscan.export.models import ScrapeResult
from ciberwebscan.services.download_service import DownloadService
from ciberwebscan.services.scrape_service import ScrapeOptions, ScrapeService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/scrape", response_model=APIResponse[ScrapeResult | list[dict[str, Any]]])
async def scrape_url(
    request: ScrapeRequest,
    http_request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[ScrapeResult | list[dict[str, Any]]]:
    """
    Scrape a single URL and return structured data.
    Supports both static (BeautifulSoup) and dynamic (Playwright) scraping.
    """
    try:
        # Convert request to service options
        options = ScrapeOptions(
            url=str(request.url),
            dynamic=request.dynamic,
            wait_for=request.wait_for,
            timeout=request.timeout,
            selector=request.selector,
            attributes=request.attributes,
            schema=request.extraction_schema,
            pagination_selector=request.pagination_selector,
            pagination_limit=request.pagination_limit,
            export=request.export,
            export_format=request.export_format,
            headers=request.headers,
            cookies=request.cookies,
            proxy=request.proxy,
            user_agent=request.user_agent,
            check_robots=request.check_robots,
            extract_forms=request.extract_forms,
        )

        # Execute scraping
        service = ScrapeService()
        result = service.scrape(options)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error or "Scraping failed",
            )

        if result.data is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scraping returned no data",
            )

        # Enrich response with download token
        download_service = DownloadService()
        data, download_token, download_url = enrich_response_with_token(
            result, user.identifier, download_service, http_request
        )

        return APIResponse[ScrapeResult | list[dict[str, Any]]](
            success=True,
            data=data,
            download_token=download_token,
            download_url=download_url,
        )

    except ValidationError as e:
        logger.warning(f"Validation error in scrape request: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid request: {e}",
        ) from e
    except Exception as e:
        logger.error(f"Error scraping URL {request.url}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scraping failed: {str(e)}",
        ) from e


@router.post("/scrape/batch", response_model=APIResponse[ScrapeBatchResultResponse])
async def scrape_batch(
    request: ScrapeBatchRequest,
    http_request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[ScrapeBatchResultResponse]:
    """
    Scrape multiple URLs in batch.
    """
    try:
        urls = [str(url) for url in request.urls]
        options = ScrapeOptions(
            url=urls[0],
            dynamic=request.dynamic,
            timeout=request.timeout,
            selector=request.selector,
            export=request.export,
            export_format=request.export_format,
            headers=request.headers,
            cookies=request.cookies,
            proxy=request.proxy,
            user_agent=request.user_agent,
            extract_forms=request.extract_forms,
        )

        service = ScrapeService()
        result = service.scrape_multiple(urls, options)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error or "Batch scraping failed",
            )

        successful_results = result.data or []
        successful_urls = {item.url for item in successful_results}
        failed_urls = [
            {"url": url, "error": "Scrape failed"}
            for url in urls
            if url not in successful_urls
        ]

        job_id = str(uuid.uuid4())
        logger.info(
            "Batch scrape completed: %s (%d success, %d failed)",
            job_id,
            len(successful_results),
            len(failed_urls),
        )

        # Create batch result data
        batch_data = ScrapeBatchResultResponse(
            job_id=job_id,
            results=successful_results,
            failed_urls=failed_urls,
            total_success=len(successful_results),
            total_failed=len(failed_urls),
            elapsed_seconds=result.duration_seconds,
        )

        # Enrich response with download token if exported
        download_service = DownloadService()
        download_token = None
        download_url = None

        if result.export_path:
            token_result = download_service.generate_download_token(
                file_path=result.export_path,
                user_id=user.identifier,
                file_format=request.export_format,
            )
            if token_result.success and token_result.data:
                download_token = token_result.data.token
                download_url = urlparse(
                    str(http_request.url_for("download_file", token=download_token))
                ).path

        return APIResponse[ScrapeBatchResultResponse](
            success=True,
            data=batch_data,
            download_token=download_token,
            download_url=download_url,
        )

    except ValidationError as e:
        logger.warning(f"Validation error in batch scrape request: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid request: {e}",
        ) from e
    except Exception as e:
        logger.error(f"Error in batch scraping: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch scraping failed: {str(e)}",
        ) from e
