"""
Scraping endpoints for CiberWebScan API.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError

from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.api.models.requests import ScrapeBatchRequest, ScrapeRequest
from ciberwebscan.api.models.responses import (
    APIResponse,
    ScrapeBatchResultResponse,
)
from ciberwebscan.export.models import ScrapeResult
from ciberwebscan.services.scrape_service import ScrapeOptions, ScrapeService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/scrape", response_model=APIResponse[ScrapeResult | list[dict[str, Any]]])
async def scrape_url(
    request: ScrapeRequest,
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

        return APIResponse[ScrapeResult | list[dict[str, Any]]](data=result.data)

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


@router.post("/scrape/batch", response_model=ScrapeBatchResultResponse)
async def scrape_batch(
    request: ScrapeBatchRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> ScrapeBatchResultResponse:
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

        return ScrapeBatchResultResponse(
            job_id=job_id,
            results=successful_results,
            failed_urls=failed_urls,
            total_success=len(successful_results),
            total_failed=len(failed_urls),
            elapsed_seconds=result.duration_seconds,
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
