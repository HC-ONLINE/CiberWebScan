"""
Scrape service for CiberWebScan.

Orchestrates web scraping operations using core scraping modules.
Supports static and dynamic scraping with optional export.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from bs4 import BeautifulSoup

from ciberwebscan.config.models import ScrapingConfig
from ciberwebscan.core.scraping import (
    DataExtractor,
    ScrapeConfig,
    StaticScraper,
    is_playwright_available,
)
from ciberwebscan.core.scraping import (
    ScrapeResult as CoreScrapeResult,
)
from ciberwebscan.core.scraping.helpers import process_elements
from ciberwebscan.export.models import ScrapeResult
from ciberwebscan.services.base import (
    BaseService,
    ExecutionError,
    ServiceResult,
    ValidationError,
)

logger = logging.getLogger(__name__)


@dataclass
class ScrapeOptions:
    """Options for scraping operations."""

    # Target
    url: str

    # Scraping mode
    dynamic: bool = False
    wait_for: str | None = None
    timeout: float = 30.0

    # Content extraction
    selector: str | None = None
    attributes: list[str] = field(default_factory=list)
    schema: dict[str, Any] | None = None

    # Pagination
    pagination_selector: str | None = None
    pagination_limit: int = 10

    # Export
    export: str | None = None  # Path to export file
    export_format: str = "json"  # json, jsonl, csv

    # Advanced
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    user_agent: str | None = None
    check_robots: bool = True


class ScrapeService(BaseService):
    """
    Service for web scraping operations.

    Provides high-level interface for:
    - Single page scraping (static or dynamic)
    - Multi-page scraping with pagination
    - Structured data extraction
    - Result export

    Example:
        service = ScrapeService()
        result = service.scrape(ScrapeOptions(
            url="https://example.com",
            selector="div.product",
            export="products.json"
        ))
        if result.success:
            print(f"Scraped: {result.data.title}")
    """

    def __init__(self, config: ScrapingConfig | None = None):
        """
        Initialize scrape service.

        Args:
            config: Scraping configuration. Uses defaults if not provided.
        """
        super().__init__()
        self.config = config or ScrapingConfig()
        self._static_scraper: StaticScraper | None = None
        self._dynamic_scraper: Any = None  # Optional DynamicScraper

    @property
    def static_scraper(self) -> StaticScraper:
        """Get or create static scraper instance."""
        if self._static_scraper is None:
            from ciberwebscan.core.client import HTTPClient

            client = HTTPClient()
            self._static_scraper = StaticScraper(client)
        return self._static_scraper

    def _get_static_scraper_with_proxy(
        self, proxy: str | None, verify_ssl: bool = True
    ) -> StaticScraper:
        """Get static scraper with specific proxy configuration."""
        if proxy or not verify_ssl:
            from ciberwebscan.core.client import HTTPClient

            client = HTTPClient(proxy=proxy, verify=verify_ssl)
            return StaticScraper(client)
        else:
            return self.static_scraper

    @property
    def dynamic_scraper(self) -> Any:
        """Get or create dynamic scraper instance."""
        if self._dynamic_scraper is None and is_playwright_available():
            from ciberwebscan.core.scraping import DynamicScraper

            self._dynamic_scraper = DynamicScraper()
        return self._dynamic_scraper

    def scrape(
        self, options: ScrapeOptions
    ) -> ServiceResult[ScrapeResult | list[dict]]:
        """
        Perform a scraping operation.

        Args:
            options: Scraping options.

        Returns:
            ServiceResult containing scraped data.
        """
        result = ServiceResult[ScrapeResult | list[dict]](success=False)

        try:
            # Validate URL
            url = self._validate_url(options.url)
            self.logger.info(f"Scraping: {url}")

            # Choose scraper
            if options.dynamic:
                if not is_playwright_available():
                    raise ExecutionError(
                        "Dynamic scraping requires playwright. "
                        "Install with: pip install playwright && playwright install"
                    )
                scraped = self._scrape_dynamic(url, options)
            else:
                scraped = self._scrape_static(url, options)

            # Extract structured data if selector provided
            if options.selector:
                extracted = self._extract_data(scraped, options)
                result.data = extracted
            else:
                result.data = scraped

            result.success = True

            # Handle export if requested
            if options.export:
                exported, path = self._export_result(
                    result.data,
                    options.export,
                    options.export_format,
                )
                result.exported = exported
                result.export_path = path
                result.export_format = options.export_format

        except ValidationError as e:
            result.error = str(e)
            result.error_code = e.code
            self.logger.error(f"Validation error: {e}")
        except ExecutionError as e:
            result.error = str(e)
            result.error_code = e.code
            self.logger.error(f"Execution error: {e}")
        except Exception as e:
            result.error = str(e)
            result.error_code = "UNEXPECTED_ERROR"
            self.logger.exception(f"Unexpected error during scrape: {e}")

        return result.finalize()

    def scrape_multiple(
        self,
        urls: list[str],
        options: ScrapeOptions,
    ) -> ServiceResult[list[ScrapeResult]]:
        """
        Scrape multiple URLs.

        Args:
            urls: List of URLs to scrape.
            options: Common options for all URLs.

        Returns:
            ServiceResult containing list of results.
        """
        result = ServiceResult[list[ScrapeResult]](success=False)
        results: list[ScrapeResult] = []
        errors: list[str] = []

        try:
            for url in urls:
                opts = ScrapeOptions(
                    url=url,
                    dynamic=options.dynamic,
                    timeout=options.timeout,
                    selector=options.selector,
                    attributes=options.attributes,
                    headers=options.headers,
                    cookies=options.cookies,
                )
                single_result = self.scrape(opts)

                if single_result.success and single_result.data:
                    if isinstance(single_result.data, ScrapeResult):
                        results.append(single_result.data)
                else:
                    errors.append(f"{url}: {single_result.error}")
                    result.warnings.append(f"Failed to scrape {url}")

            result.data = results
            result.success = len(results) > 0

            # Export all results if requested
            if options.export and results:
                exported, path = self._export_result(
                    results,
                    options.export,
                    options.export_format,
                )
                result.exported = exported
                result.export_path = path

        except Exception as e:
            result.error = str(e)
            result.error_code = "UNEXPECTED_ERROR"

        return result.finalize()

    def _scrape_static(self, url: str, options: ScrapeOptions) -> ScrapeResult:
        """Perform static scraping."""
        try:
            config = ScrapeConfig(
                selector=options.selector or "body",
                schema=options.schema,
                timeout=options.timeout,
                headers=options.headers or None,
                cookies=options.cookies or None,
                check_robots=options.check_robots,
            )

            core_result: CoreScrapeResult = self._get_static_scraper_with_proxy(
                options.proxy, config.verify_ssl
            ).scrape(url, config)

            # Map core ScrapeResult to export ScrapeResult
            return ScrapeResult(
                url=url,
                status_code=core_result.status_code or 0,
                content_type="",
                title="",
                text_content=(core_result.html or "")[:10000],
                raw_html=(core_result.html or None),
                headers={},
                elapsed_ms=(core_result.elapsed_time or 0.0) * 1000,
            )

        except Exception as e:
            raise ExecutionError(f"Static scraping failed: {e}") from e

    def _scrape_dynamic(self, url: str, options: ScrapeOptions) -> ScrapeResult:
        """Perform dynamic scraping with browser."""
        try:
            import asyncio

            from ciberwebscan.core.scraping import DynamicScrapeConfig

            config = DynamicScrapeConfig(
                selector=options.selector or "body",
                wait_selector=options.wait_for,
                schema=options.schema,
            )

            # Run the async scrape method in the current event loop
            try:
                loop = asyncio.get_running_loop()
                # If we're already in an async context, we need to handle it properly
                # For now, let's use a simpler approach and run it sync
                core_result = loop.run_until_complete(
                    self.dynamic_scraper.scrape(url, config)
                )
            except RuntimeError:
                # No running loop - create one to run the coroutine
                core_result = asyncio.run(self.dynamic_scraper.scrape(url, config))

            # dynamic scraper returns DynamicScrapeResult-like dataclass
            return ScrapeResult(
                url=url,
                status_code=200
                if getattr(core_result, "status_code", None) is None
                else core_result.status_code,
                content_type="text/html",
                title="",
                text_content=(getattr(core_result, "html", None) or "")[:10000],
                raw_html=(getattr(core_result, "html", None) or None),
                headers={},
                elapsed_ms=(getattr(core_result, "elapsed_time", 0.0) or 0.0) * 1000,
            )

        except Exception as e:
            raise ExecutionError(f"Dynamic scraping failed: {e}") from e

    def _extract_data(
        self,
        scraped: ScrapeResult,
        options: ScrapeOptions,
    ) -> list[dict[str, Any]]:
        """Extract structured data from scraped content."""
        try:
            extractor = DataExtractor()
            html = scraped.text_content or ""
            soup = BeautifulSoup(html, "html.parser")

            if options.schema:
                schema = options.schema
                return extractor.extract_many(soup, options.selector or "body", schema)
            elif options.selector:
                elements = soup.select(options.selector)
                return process_elements(
                    elements, attributes=options.attributes or ["text", "href"]
                )
            else:
                return []

        except Exception as e:
            self.logger.warning(f"Data extraction failed: {e}")
            return []

    def close(self) -> None:
        """Clean up resources properly handling async/sync contexts."""
        import asyncio
        import contextlib

        # 1. Close StaticScraper's HTTPClient
        if self._static_scraper:
            with contextlib.suppress(Exception):
                if hasattr(self._static_scraper, "_client"):
                    self._static_scraper._client.close()
            self._static_scraper = None

        # 2. Close DynamicScraper's Playwright browser (async)
        if self._dynamic_scraper:
            try:
                # _close_browser is async - need to run it properly
                coro = self._dynamic_scraper._close_browser()
                try:
                    loop = asyncio.get_running_loop()
                    # Already in async context - schedule as task
                    loop.create_task(coro)
                except RuntimeError:
                    # No running loop - create one to run the coroutine
                    asyncio.run(coro)
            except Exception as e:
                self.logger.warning(f"Failed to close dynamic scraper: {e}")
            finally:
                self._dynamic_scraper = None

    def __enter__(self) -> ScrapeService:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
