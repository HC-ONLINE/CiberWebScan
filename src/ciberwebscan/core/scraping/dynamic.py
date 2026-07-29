"""
Dynamic web scraping module using Playwright.

Provides browser-based scraping for JavaScript-rendered pages,
with support for page interactions, waiting conditions, and
structured extraction.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from bs4 import BeautifulSoup

from ciberwebscan.core.scraping.extractor import DataExtractor
from ciberwebscan.core.scraping.helpers import (
    check_robots_txt,
    find_next_page_url,
    is_safe_url,
    parse_cookie_string,
    process_elements,
)

if TYPE_CHECKING:
    from playwright._impl._api_structures import SetCookieParam
    from playwright.async_api import Browser, BrowserContext, Page

    from ciberwebscan.core.client.http_client import HTTPClient
    from ciberwebscan.core.client.proxy import ProxyRotator
    from ciberwebscan.core.client.user_agent import UserAgentProvider

logger = logging.getLogger(__name__)


class BrowserType(Enum):
    """Supported browser types."""

    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


class WaitStrategy(Enum):
    """Page load wait strategies."""

    LOAD = "load"  # Wait for 'load' event
    DOMCONTENTLOADED = "domcontentloaded"  # Wait for DOMContentLoaded
    NETWORKIDLE = "networkidle"  # Wait until no network requests for 500ms


@dataclass
class DynamicScrapeConfig:
    """Configuration for dynamic scraping operations."""

    selector: str
    """CSS selector for target elements."""

    wait_selector: str | None = None
    """CSS selector to wait for before scraping."""

    wait_timeout: float = 30.0
    """Timeout for waiting conditions in seconds."""

    wait_strategy: WaitStrategy = WaitStrategy.NETWORKIDLE
    """Page load wait strategy."""

    pagination_selector: str | None = None
    """CSS selector for next page link/button."""

    max_pages: int = 1
    """Maximum number of pages to scrape."""

    page_delay: float = 1.0
    """Delay between page navigations in seconds."""

    browser_type: BrowserType = BrowserType.CHROMIUM
    """Browser type to use."""

    headless: bool = True
    """Whether to run browser in headless mode."""

    viewport_width: int = 1920
    """Browser viewport width."""

    viewport_height: int = 1080
    """Browser viewport height."""

    cookies: dict[str, str] | str | None = None
    """Cookies to inject into browser."""

    user_agent: str | None = None
    """Custom user agent string."""

    proxy: str | None = None
    """Proxy server URL."""

    check_robots: bool = True
    """Whether to respect robots.txt."""

    allow_local: bool = False
    """Whether to allow scraping local/private IPs."""

    attributes: list[str] | None = None
    """Specific attributes to extract from elements."""

    schema: dict[str, Any] | None = None
    """Structured extraction schema."""

    javascript_enabled: bool = True
    """Whether JavaScript is enabled."""

    scroll_to_bottom: bool = False
    """Whether to scroll to bottom before scraping (for infinite scroll)."""

    scroll_delay: float = 0.5
    """Delay between scroll steps in seconds."""

    block_resources: list[str] | None = None
    """Resource types to block (e.g., ['image', 'stylesheet', 'font'])."""


@dataclass
class DynamicScrapeResult:
    """Result from a dynamic scraping operation."""

    url: str
    """URL that was scraped."""

    success: bool
    """Whether the scrape was successful."""

    data: list[dict[str, Any]] = field(default_factory=list)
    """Extracted data from the page."""

    html: str | None = None
    """Raw HTML content after JavaScript execution."""

    title: str = ""
    """Page title extracted from HTML."""

    links: list[dict[str, str]] = field(default_factory=list)
    """Links extracted from the page."""

    images: list[dict[str, str]] = field(default_factory=list)
    """Images extracted from the page."""

    forms: list[dict[str, Any]] = field(default_factory=list)
    """Forms extracted from the page."""

    scripts: list[dict[str, str]] = field(default_factory=list)
    """Scripts extracted from the page."""

    error: str | None = None
    """Error message if scraping failed."""

    page_number: int = 1
    """Page number in pagination sequence."""

    elapsed_time: float = 0.0
    """Time taken for the operation in seconds."""

    screenshot: bytes | None = None
    """Optional screenshot of the page."""


@dataclass
class DynamicScrapePagesResult:
    """Result from multi-page dynamic scraping."""

    pages: list[DynamicScrapeResult] = field(default_factory=list)
    """Results from each page."""

    total_items: int = 0
    """Total number of items extracted."""

    @property
    def success(self) -> bool:
        """Whether at least one page was successful."""
        return any(p.success for p in self.pages)

    @property
    def all_data(self) -> list[dict[str, Any]]:
        """Combined data from all pages."""
        return [item for page in self.pages for item in page.data]


class DynamicScraper:
    """
    Dynamic web scraper using Playwright.

    This scraper is suitable for JavaScript-rendered pages that
    require a real browser to render content. It supports waiting
    for elements, page interactions, and structured extraction.

    Examples:
        >>> from ciberwebscan.core.scraping import DynamicScraper, DynamicScrapeConfig
        >>>
        >>> async with DynamicScraper() as scraper:
        ...     config = DynamicScrapeConfig(
        ...         selector='div.product',
        ...         wait_selector='div.product',
        ...         schema={'name': {'selector': '.title'}},
        ...     )
        ...     result = await scraper.scrape('https://example.com', config)

    Note:
        This scraper requires playwright to be installed:
        `pip install playwright && playwright install`
    """

    def __init__(
        self,
        *,
        http_client: HTTPClient | None = None,
        proxy_rotator: ProxyRotator | None = None,
        user_agent_provider: UserAgentProvider | None = None,
    ) -> None:
        """
        Initialize the dynamic scraper.

        Args:
            http_client: Optional HTTP client for robots.txt checks.
            proxy_rotator: Optional proxy rotator for IP rotation.
            user_agent_provider: Optional user agent provider for UA rotation.
        """
        self._http_client = http_client
        self._proxy_rotator = proxy_rotator
        self._ua_provider = user_agent_provider
        self._extractor = DataExtractor()
        self._playwright = None
        self._browser: Browser | None = None

    async def __aenter__(self) -> DynamicScraper:
        """Async context manager entry."""
        await self._start_browser()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self._close_browser()

    async def _start_browser(
        self,
        browser_type: BrowserType = BrowserType.CHROMIUM,
        headless: bool = True,
    ) -> None:
        """Start the browser instance."""
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()

        browser_launcher = getattr(self._playwright, browser_type.value)
        self._browser = await browser_launcher.launch(headless=headless)
        logger.debug("Browser started: %s (headless=%s)", browser_type.value, headless)

    async def _close_browser(self) -> None:
        """Close the browser instance."""
        if self._browser:
            await self._browser.close()
            self._browser = None

        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def scrape(
        self,
        url: str,
        config: DynamicScrapeConfig,
    ) -> DynamicScrapeResult:
        """
        Scrape a single page dynamically.

        Args:
            url: URL to scrape.
            config: Scraping configuration.

        Returns:
            DynamicScrapeResult with extracted data.

        Examples:
            >>> config = DynamicScrapeConfig(
            ...     selector='div.item',
            ...     wait_selector='.content-loaded',
            ... )
            >>> result = await scraper.scrape('https://example.com', config)
        """
        # Validate URL
        if not is_safe_url(url, allow_local=config.allow_local):
            return DynamicScrapeResult(
                url=url,
                success=False,
                error="Invalid or unsafe URL",
            )

        # Check robots.txt
        if config.check_robots:
            user_agent = config.user_agent or self._get_user_agent()
            allowed, reason = check_robots_txt(
                url,
                user_agent,
                http_client=self._http_client,
            )
            if not allowed:
                return DynamicScrapeResult(
                    url=url,
                    success=False,
                    error=reason or "Blocked by robots.txt",
                )

        # Ensure browser is started
        if not self._browser:
            await self._start_browser(config.browser_type, config.headless)

        start_time = time.time()

        try:
            # Create context with configuration
            context = await self._create_context(config, url)

            try:
                page = await context.new_page()
                await self._setup_page(page, config)

                # Navigate to URL
                await page.goto(
                    url,
                    wait_until=config.wait_strategy.value,
                    timeout=config.wait_timeout * 1000,
                )

                # Wait for selector if specified
                if config.wait_selector:
                    await page.wait_for_selector(
                        config.wait_selector,
                        timeout=config.wait_timeout * 1000,
                    )

                # Scroll to bottom if needed (for infinite scroll pages)
                if config.scroll_to_bottom:
                    await self._scroll_to_bottom(page, config.scroll_delay)

                # Get HTML content
                html = await page.content()

                # Parse and extract data
                soup = BeautifulSoup(html, "html.parser")
                data = self._extract_data(soup, config)

                # Extract metadata from HTML
                title = ""
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()

                from ciberwebscan.core.scraping.extractor import (
                    extract_forms,
                    extract_images,
                    extract_links,
                    extract_scripts,
                )

                links = extract_links(soup)
                images = extract_images(soup)
                forms = extract_forms(soup)
                scripts = extract_scripts(soup)

                elapsed = time.time() - start_time
                if elapsed == 0.0:
                    elapsed = 1e-6

                return DynamicScrapeResult(
                    url=url,
                    success=True,
                    data=data,
                    html=html,
                    title=title,
                    links=links,
                    images=images,
                    forms=forms,
                    scripts=scripts,
                    elapsed_time=elapsed,
                )

            finally:
                await context.close()

        except Exception as e:
            elapsed = time.time() - start_time
            if elapsed == 0.0:
                elapsed = 1e-6
            logger.exception("Error scraping %s dynamically", url)
            return DynamicScrapeResult(
                url=url,
                success=False,
                error=str(e),
                elapsed_time=elapsed,
            )

    async def scrape_pages(
        self,
        url: str,
        config: DynamicScrapeConfig,
    ) -> DynamicScrapePagesResult:
        """
        Scrape multiple pages following pagination.

        Args:
            url: Starting URL.
            config: Scraping configuration with pagination_selector.

        Returns:
            DynamicScrapePagesResult with all extracted data.
        """
        results = []
        async for result in self.scrape_pages_stream(url, config):
            results.append(result)

        return DynamicScrapePagesResult(
            pages=results,
            total_items=sum(len(r.data) for r in results),
        )

    async def scrape_pages_stream(
        self,
        url: str,
        config: DynamicScrapeConfig,
    ) -> AsyncGenerator[DynamicScrapeResult, None]:
        """
        Stream scrape results page by page.

        Args:
            url: Starting URL.
            config: Scraping configuration.

        Yields:
            DynamicScrapeResult for each page.
        """
        current_url = url
        page_number = 0

        while current_url and page_number < config.max_pages:
            page_number += 1

            result = await self.scrape(current_url, config)
            result.page_number = page_number
            yield result

            if not result.success:
                break

            # Find next page
            if not config.pagination_selector or not result.html:
                break

            soup = BeautifulSoup(result.html, "html.parser")
            next_url = find_next_page_url(
                soup,
                config.pagination_selector,
                current_url,
            )

            if not next_url or next_url == current_url:
                break

            current_url = next_url

            # Delay between pages
            if page_number < config.max_pages:
                await asyncio.sleep(config.page_delay)

    async def _create_context(
        self,
        config: DynamicScrapeConfig,
        target_url: str | None = None,
    ) -> BrowserContext:
        """Create a browser context with configuration."""
        context_options = {
            "viewport": {
                "width": config.viewport_width,
                "height": config.viewport_height,
            },
            "java_script_enabled": config.javascript_enabled,
        }

        # Set user agent
        user_agent = config.user_agent or self._get_user_agent()
        if user_agent:
            context_options["user_agent"] = user_agent

        # Set proxy
        proxy = config.proxy or self._get_proxy()
        if proxy:
            context_options["proxy"] = {"server": proxy}

        assert self._browser is not None  # Ensured by caller
        context = await self._browser.new_context(**context_options)

        # Set cookies
        if config.cookies:
            cookies = self._prepare_cookies(config.cookies)
            if cookies:
                await self._set_cookies_for_context(context, cookies, target_url)

        return context

    async def _set_cookies_for_context(
        self,
        context: BrowserContext,
        cookies: dict[str, str],
        target_url: str | None = None,
    ) -> None:
        """Set cookies for the browser context."""
        from urllib.parse import urlparse

        # Extract domain from target URL or use a default
        if target_url:
            parsed = urlparse(target_url)
            domain = parsed.hostname or "localhost"
            # Add leading dot for subdomain support if it's not localhost
            if domain != "localhost" and not domain.startswith("."):
                domain = f".{domain}"
        else:
            domain = "localhost"

        # Convert to Playwright cookie format
        playwright_cookies: list[SetCookieParam] = [
            {
                "name": k,
                "value": v,
                "domain": domain,
                "path": "/",
            }
            for k, v in cookies.items()
        ]

        await context.add_cookies(playwright_cookies)

    async def _setup_page(
        self,
        page: Page,
        config: DynamicScrapeConfig,
    ) -> None:
        """Set up page with request interception if needed."""
        if config.block_resources:
            block_list = config.block_resources  # Capture for lambda
            await page.route(
                "**/*",
                lambda route: self._handle_route(route, block_list),
            )

    async def _handle_route(
        self,
        route,
        block_resources: list[str],
    ) -> None:
        """Handle route for resource blocking."""
        if route.request.resource_type in block_resources:
            await route.abort()
        else:
            await route.continue_()

    async def _scroll_to_bottom(
        self,
        page: Page,
        delay: float,
    ) -> None:
        """Scroll to the bottom of the page for infinite scroll."""
        previous_height = 0
        max_scrolls = 50  # Safety limit

        for _ in range(max_scrolls):
            current_height = await page.evaluate("document.body.scrollHeight")

            if current_height == previous_height:
                break

            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(delay)
            previous_height = current_height

    def _extract_data(
        self,
        soup: BeautifulSoup,
        config: DynamicScrapeConfig,
    ) -> list[dict[str, Any]]:
        """Extract data from parsed HTML."""
        elements = soup.select(config.selector)

        if config.schema:
            return [self._extractor.extract(el, config.schema) for el in elements]
        elif config.attributes:
            return process_elements(elements, attributes=config.attributes)
        else:
            return process_elements(elements)

    def _prepare_cookies(
        self,
        cookies: dict[str, str] | str | None,
    ) -> dict[str, str] | None:
        """Prepare cookies."""
        if cookies is None:
            return None

        if isinstance(cookies, str):
            return parse_cookie_string(cookies)

        return cookies

    def _get_user_agent(self) -> str:
        """Get user agent string."""
        if self._ua_provider:
            return self._ua_provider.get()

        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def _get_proxy(self) -> str | None:
        """Get proxy URL."""
        if self._proxy_rotator:
            return self._proxy_rotator.next()
        return None


async def scrape_dynamic(
    url: str,
    selector: str,
    *,
    schema: dict[str, Any] | None = None,
    attributes: list[str] | None = None,
    wait_selector: str | None = None,
    max_pages: int = 1,
    pagination_selector: str | None = None,
    headless: bool = True,
    check_robots: bool = True,
) -> DynamicScrapePagesResult:
    """
    Convenience function for dynamic scraping.

    Args:
        url: URL to scrape.
        selector: CSS selector for target elements.
        schema: Optional structured extraction schema.
        attributes: Optional list of attributes to extract.
        wait_selector: Optional selector to wait for.
        max_pages: Maximum pages to scrape.
        pagination_selector: CSS selector for next page.
        headless: Whether to run in headless mode.
        check_robots: Whether to respect robots.txt.

    Returns:
        DynamicScrapePagesResult with extracted data.

    Examples:
        >>> result = await scrape_dynamic(
        ...     'https://example.com/spa',
        ...     'div.item',
        ...     wait_selector='.loaded',
        ...     schema={'title': {'selector': 'h2'}},
        ... )
    """
    config = DynamicScrapeConfig(
        selector=selector,
        schema=schema,
        attributes=attributes,
        wait_selector=wait_selector,
        max_pages=max_pages,
        pagination_selector=pagination_selector,
        headless=headless,
        check_robots=check_robots,
    )

    async with DynamicScraper() as scraper:
        return await scraper.scrape_pages(url, config)


def scrape_dynamic_sync(
    url: str,
    selector: str,
    **kwargs,
) -> DynamicScrapePagesResult:
    """
    Synchronous wrapper for dynamic scraping.

    This is a convenience function for use in non-async contexts.
    For better performance in async applications, use `scrape_dynamic`.

    Args:
        url: URL to scrape.
        selector: CSS selector for target elements.
        **kwargs: Additional arguments passed to scrape_dynamic.

    Returns:
        DynamicScrapePagesResult with extracted data.

    Examples:
        >>> result = scrape_dynamic_sync(
        ...     'https://example.com/spa',
        ...     'div.item',
        ...     wait_selector='.loaded',
        ... )
    """
    return asyncio.run(scrape_dynamic(url, selector, **kwargs))
