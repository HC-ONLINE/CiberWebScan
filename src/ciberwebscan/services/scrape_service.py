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

from ciberwebscan.config.loader import get_config
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
from ciberwebscan.utils.async_runner import run_async

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
    extract_forms: bool = False


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
        self.app_config = get_config()
        self.config = config or self.app_config.scraping
        self._static_scraper: StaticScraper | None = None
        self._dynamic_scraper: Any = None  # Optional DynamicScraper

        # Initialize user agent provider from config
        from ciberwebscan.core.client.user_agent import UserAgentProvider

        self._user_agent_provider = UserAgentProvider.from_config(
            self.app_config.user_agent
        )

        # Initialize proxy rotator from config (lazy-built on first access)
        self._proxy_rotator = self._build_proxy_rotator()

    def _build_http_client(
        self,
        *,
        proxy: str | None = None,
        verify: bool | None = None,
        cookies: dict[str, str] | None = None,
    ):
        from ciberwebscan.core.client import HTTPClient

        http_config = self.app_config.http

        # Get user agent from provider
        user_agent = self._user_agent_provider.get()
        default_headers = {"User-Agent": user_agent}

        return HTTPClient(
            timeout=http_config.timeout.read,
            max_attempts=http_config.retry.max_attempts,
            backoff_factor=http_config.retry.backoff_factor,
            rate_limit=(
                http_config.rate_limit.requests_per_second
                if http_config.rate_limit.per_domain
                else None
            ),
            http2=http_config.http2,
            verify=http_config.verify_ssl if verify is None else verify,
            follow_redirects=http_config.follow_redirects,
            cookies=cookies,
            proxy=proxy,
            default_headers=default_headers,
        )

    def _build_proxy_rotator(self):
        """Build a ProxyRotator from config if proxy rotation is enabled.

        Returns:
            A :class:`ProxyRotator` instance or ``None`` when rotation is
            disabled or no proxies are available.
        """
        from ciberwebscan.core.client.proxy import ProxyRotator

        proxy_cfg = self.app_config.http.proxy
        if proxy_cfg is None or not proxy_cfg.rotate:
            return None

        # Prefer explicit proxy_list; fall back to individual proxy fields
        proxies: list[str] = []
        if proxy_cfg.proxy_list:
            proxies = list(proxy_cfg.proxy_list)
        else:
            for url in (proxy_cfg.http, proxy_cfg.https):
                if url is not None:
                    proxies.append(str(url))
            if proxy_cfg.socks5:
                proxies.append(proxy_cfg.socks5)

        if not proxies:
            logger.warning(
                "Proxy rotation enabled but no proxies configured — "
                "set proxy_list or individual proxy fields"
            )
            return None

        rotator = ProxyRotator(
            proxies=proxies,
            rotation_interval=proxy_cfg.rotation_interval,
        )
        logger.info(
            "Proxy rotation enabled: %d proxies, interval=%d",
            len(proxies),
            proxy_cfg.rotation_interval,
        )
        return rotator

    @property
    def static_scraper(self) -> StaticScraper:
        """Get or create static scraper instance."""
        if self._static_scraper is None:
            client = self._build_http_client()
            self._static_scraper = StaticScraper(
                client,
                proxy_rotator=self._proxy_rotator,
                user_agent_provider=self._user_agent_provider,
            )
        return self._static_scraper

    def _get_static_scraper_with_proxy(
        self,
        proxy: str | None,
        verify_ssl: bool = True,
        cookies: dict[str, str] | None = None,
    ) -> StaticScraper:
        """Get static scraper with specific proxy/cookies configuration."""
        if proxy or not verify_ssl or cookies:
            client = self._build_http_client(
                proxy=proxy,
                verify=verify_ssl,
                cookies=cookies,
            )
            return StaticScraper(
                client,
                proxy_rotator=self._proxy_rotator,
                user_agent_provider=self._user_agent_provider,
            )
        else:
            return self.static_scraper

    @property
    def dynamic_scraper(self) -> Any:
        """Get or create dynamic scraper instance."""
        if self._dynamic_scraper is None and is_playwright_available():
            from ciberwebscan.core.scraping import DynamicScraper

            self._dynamic_scraper = DynamicScraper(
                proxy_rotator=self._proxy_rotator,
                user_agent_provider=self._user_agent_provider,
            )
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
                    proxy=options.proxy,
                    user_agent=options.user_agent,
                    check_robots=options.check_robots,
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
            timeout = (
                self.app_config.http.timeout.read
                if options.timeout == 30.0
                else options.timeout
            )
            config = ScrapeConfig(
                selector=options.selector or "body",
                schema=options.schema,
                timeout=timeout,
                headers=options.headers or None,
                check_robots=options.check_robots,
                extract_forms=options.extract_forms,
            )

            core_result: CoreScrapeResult = self._get_static_scraper_with_proxy(
                options.proxy,
                config.verify_ssl,
                cookies=options.cookies or None,
            ).scrape(url, config)

            # Map core ScrapeResult to export ScrapeResult
            from ciberwebscan.export.models import (
                FormInfo,
                ImageInfo,
                LinkInfo,
                ScriptInfo,
            )

            return ScrapeResult(
                url=url,
                status_code=core_result.status_code or 0,
                content_type=core_result.content_type,
                title=core_result.title,
                text_content=(core_result.html or "")[:10000],
                raw_html=(core_result.html or None),
                links=[
                    LinkInfo(href=link.get("href", ""), text=link.get("text", ""))
                    for link in core_result.links
                ],
                images=[
                    ImageInfo(src=img.get("src", ""), alt=img.get("alt", ""))
                    for img in core_result.images
                ],
                forms=[
                    FormInfo(
                        action=f.get("action", ""),
                        method=f.get("method", "GET"),
                        enctype=f.get("enctype", ""),
                        id=f.get("id", ""),
                        name=f.get("name", ""),
                        fields=f.get("fields", []),
                    )
                    for f in core_result.forms
                ],
                scripts=[
                    ScriptInfo(
                        src=s.get("src"),
                        type=s.get("type", "text/javascript"),
                        hash=None,
                    )
                    for s in core_result.scripts
                ],
                headers=core_result.headers,
                cookies=core_result.cookies,
                elapsed_ms=(core_result.elapsed_time or 0.0) * 1000,
            )

        except Exception as e:
            raise ExecutionError(f"Static scraping failed: {e}") from e

    def _scrape_dynamic(self, url: str, options: ScrapeOptions) -> ScrapeResult:
        """Perform dynamic scraping with browser."""
        try:
            from ciberwebscan.core.scraping import BrowserType, DynamicScrapeConfig

            dyn_cfg = self.config.dynamic
            config = DynamicScrapeConfig(
                selector=options.selector or "body",
                wait_selector=options.wait_for or dyn_cfg.wait_selector,
                wait_timeout=dyn_cfg.wait_timeout,
                headless=dyn_cfg.headless,
                browser_type=BrowserType(dyn_cfg.browser_type),
                schema=options.schema,
                extract_forms=options.extract_forms,
            )

            # Run the async scrape method safely from sync context
            core_result = run_async(self.dynamic_scraper.scrape(url, config))

            # dynamic scraper returns DynamicScrapeResult-like dataclass
            from ciberwebscan.export.models import (
                FormInfo,
                ImageInfo,
                LinkInfo,
                ScriptInfo,
            )

            return ScrapeResult(
                url=url,
                status_code=200
                if getattr(core_result, "status_code", None) is None
                else core_result.status_code,
                content_type="text/html",
                title=getattr(core_result, "title", "") or "",
                text_content=(getattr(core_result, "html", None) or "")[:10000],
                raw_html=(getattr(core_result, "html", None) or None),
                links=[
                    LinkInfo(href=link.get("href", ""), text=link.get("text", ""))
                    for link in getattr(core_result, "links", [])
                ],
                images=[
                    ImageInfo(src=img.get("src", ""), alt=img.get("alt", ""))
                    for img in getattr(core_result, "images", [])
                ],
                forms=[
                    FormInfo(
                        action=f.get("action", ""),
                        method=f.get("method", "GET"),
                        enctype=f.get("enctype", ""),
                        id=f.get("id", ""),
                        name=f.get("name", ""),
                        fields=f.get("fields", []),
                    )
                    for f in getattr(core_result, "forms", [])
                ],
                scripts=[
                    ScriptInfo(
                        src=s.get("src"),
                        type=s.get("type", "text/javascript"),
                        hash=None,
                    )
                    for s in getattr(core_result, "scripts", [])
                ],
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
                coro = self._dynamic_scraper._close_browser()
                run_async(coro)
            except Exception as e:
                self.logger.warning(f"Failed to close dynamic scraper: {e}")
            finally:
                self._dynamic_scraper = None

    def __enter__(self) -> ScrapeService:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
