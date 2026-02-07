"""
Static web scraping module.

Provides HTTP-based scraping using BeautifulSoup for parsing,
with support for pagination, proxy rotation, and structured extraction.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Generator
from dataclasses import dataclass, field
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
    from ciberwebscan.core.client.http_client import HTTPClient
    from ciberwebscan.core.client.proxy import ProxyRotator
    from ciberwebscan.core.client.user_agent import UserAgentProvider

logger = logging.getLogger(__name__)


@dataclass
class ScrapeConfig:
    """Configuration for static scraping operations."""

    selector: str
    """CSS selector for target elements."""

    pagination_selector: str | None = None
    """CSS selector for next page link."""

    max_pages: int = 1
    """Maximum number of pages to scrape."""

    page_delay: float = 1.0
    """Delay between page requests in seconds."""

    timeout: float = 30.0
    """Request timeout in seconds."""

    verify_ssl: bool = True
    """Whether to verify SSL certificates."""

    cookies: dict[str, str] | str | None = None
    """Cookies to include with requests."""

    headers: dict[str, str] | None = None
    """Additional headers to include."""

    check_robots: bool = True
    """Whether to respect robots.txt."""

    allow_local: bool = False
    """Whether to allow scraping local/private IPs."""

    attributes: list[str] | None = None
    """Specific attributes to extract from elements."""

    schema: dict[str, Any] | None = None
    """Structured extraction schema."""


@dataclass
class ScrapeResult:
    """Result from a scraping operation."""

    url: str
    """URL that was scraped."""

    success: bool
    """Whether the scrape was successful."""

    status_code: int | None = None
    """HTTP status code."""

    data: list[dict[str, Any]] = field(default_factory=list)
    """Extracted data from the page."""

    html: str | None = None
    """Raw HTML content (if retained)."""

    error: str | None = None
    """Error message if scraping failed."""

    page_number: int = 1
    """Page number in pagination sequence."""

    elapsed_time: float = 0.0
    """Time taken for the request in seconds."""


@dataclass
class ScrapePagesResult:
    """Result from multi-page scraping."""

    pages: list[ScrapeResult] = field(default_factory=list)
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


class StaticScraper:
    """
    Static web scraper using HTTP requests and BeautifulSoup.

    This scraper is suitable for pages that don't require JavaScript
    execution. It supports pagination, proxy rotation, and structured
    data extraction.

    Examples:
        >>> from ciberwebscan.core.client import HTTPClient
        >>> from ciberwebscan.core.scraping import StaticScraper, ScrapeConfig
        >>>
        >>> client = HTTPClient()
        >>> scraper = StaticScraper(client)
        >>>
        >>> config = ScrapeConfig(
        ...     selector='div.product',
        ...     pagination_selector='a.next',
        ...     max_pages=5,
        ...     schema={'name': {'selector': '.title'}, 'price': {'selector': '.price'}},
        ... )
        >>> result = scraper.scrape('https://example.com/products', config)
    """

    def __init__(
        self,
        http_client: HTTPClient,
        *,
        proxy_rotator: ProxyRotator | None = None,
        user_agent_provider: UserAgentProvider | None = None,
    ) -> None:
        """
        Initialize the static scraper.

        Args:
            http_client: HTTP client for making requests.
            proxy_rotator: Optional proxy rotator for IP rotation.
            user_agent_provider: Optional user agent provider for UA rotation.
        """
        self._client = http_client
        self._proxy_rotator = proxy_rotator
        self._ua_provider = user_agent_provider
        self._extractor = DataExtractor()

    def scrape(
        self,
        url: str,
        config: ScrapeConfig,
    ) -> ScrapeResult:
        """
        Scrape a single page.

        Args:
            url: URL to scrape.
            config: Scraping configuration.

        Returns:
            ScrapeResult with extracted data.

        Examples:
            >>> config = ScrapeConfig(selector='article', attributes=['title', 'href'])
            >>> result = scraper.scrape('https://example.com', config)
            >>> if result.success:
            ...     print(f"Found {len(result.data)} items")
        """
        # Validate URL
        if not is_safe_url(url, allow_local=config.allow_local):
            return ScrapeResult(
                url=url,
                success=False,
                error="Invalid or unsafe URL",
            )

        # Check robots.txt
        if config.check_robots:
            user_agent = self._get_user_agent()
            allowed, reason = check_robots_txt(
                url,
                user_agent,
                http_client=self._client,
            )
            if not allowed:
                return ScrapeResult(
                    url=url,
                    success=False,
                    error=reason or "Blocked by robots.txt",
                )

        # Prepare request
        headers = self._prepare_headers(config.headers)
        cookies = self._prepare_cookies(config.cookies)

        # Make request
        start_time = time.time()
        try:
            response = self._client.get(
                url,
                headers=headers,
                cookies=cookies,
                timeout=config.timeout,
            )
            elapsed = time.time() - start_time

            # Check for error status codes
            if response.status_code >= 400:
                return ScrapeResult(
                    url=url,
                    success=False,
                    status_code=response.status_code,
                    error=f"HTTP {response.status_code}",
                    elapsed_time=elapsed,
                )

            # Parse and extract
            soup = BeautifulSoup(response.text, "html.parser")
            data = self._extract_data(soup, config)

            return ScrapeResult(
                url=url,
                success=True,
                status_code=response.status_code,
                data=data,
                html=response.text,
                elapsed_time=elapsed,
            )

        except Exception as e:
            elapsed = time.time() - start_time
            logger.exception("Error scraping %s", url)
            return ScrapeResult(
                url=url,
                success=False,
                error=str(e),
                elapsed_time=elapsed,
            )

    def scrape_pages(
        self,
        url: str,
        config: ScrapeConfig,
    ) -> ScrapePagesResult:
        """
        Scrape multiple pages following pagination.

        Args:
            url: Starting URL.
            config: Scraping configuration with pagination_selector.

        Returns:
            ScrapePagesResult with all extracted data.

        Examples:
            >>> config = ScrapeConfig(
            ...     selector='div.item',
            ...     pagination_selector='a.next-page',
            ...     max_pages=10,
            ... )
            >>> result = scraper.scrape_pages('https://example.com/list', config)
            >>> print(f"Scraped {len(result.pages)} pages")
        """
        results = list(self.scrape_pages_stream(url, config))
        return ScrapePagesResult(
            pages=results,
            total_items=sum(len(r.data) for r in results),
        )

    def scrape_pages_stream(
        self,
        url: str,
        config: ScrapeConfig,
    ) -> Generator[ScrapeResult, None, None]:
        """
        Stream scrape results page by page.

        This is memory-efficient for large scraping operations as it
        yields results as they're fetched.

        Args:
            url: Starting URL.
            config: Scraping configuration.

        Yields:
            ScrapeResult for each page.

        Examples:
            >>> for page_result in scraper.scrape_pages_stream(url, config):
            ...     for item in page_result.data:
            ...         process(item)
        """
        current_url = url
        page_number = 0

        while current_url and page_number < config.max_pages:
            page_number += 1

            # Scrape current page
            result = self._scrape_page_internal(current_url, config, page_number)
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
                time.sleep(config.page_delay)

    def _scrape_page_internal(
        self,
        url: str,
        config: ScrapeConfig,
        page_number: int,
    ) -> ScrapeResult:
        """Internal method to scrape a single page."""
        result = self.scrape(url, config)
        result.page_number = page_number
        return result

    def _extract_data(
        self,
        soup: BeautifulSoup,
        config: ScrapeConfig,
    ) -> list[dict[str, Any]]:
        """Extract data from parsed HTML."""
        elements = soup.select(config.selector)

        if config.schema:
            # Use structured extraction
            return [self._extractor.extract(el, config.schema) for el in elements]
        elif config.attributes:
            # Use attribute extraction
            return process_elements(elements, attributes=config.attributes)
        else:
            # Default: extract text and common attributes
            return process_elements(elements)

    def _prepare_headers(
        self,
        custom_headers: dict[str, str] | None,
    ) -> dict[str, str]:
        """Prepare request headers."""
        headers = {
            "User-Agent": self._get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        if custom_headers:
            headers.update(custom_headers)

        return headers

    def _prepare_cookies(
        self,
        cookies: dict[str, str] | str | None,
    ) -> dict[str, str] | None:
        """Prepare cookies for request."""
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


def scrape_static(
    url: str,
    selector: str,
    *,
    http_client: HTTPClient | None = None,
    schema: dict[str, Any] | None = None,
    attributes: list[str] | None = None,
    max_pages: int = 1,
    pagination_selector: str | None = None,
    check_robots: bool = True,
    cookies: dict[str, str] | str | None = None,
) -> ScrapePagesResult:
    """
    Convenience function for static scraping.

    Args:
        url: URL to scrape.
        selector: CSS selector for target elements.
        http_client: Optional HTTP client (creates one if not provided).
        schema: Optional structured extraction schema.
        attributes: Optional list of attributes to extract.
        max_pages: Maximum pages to scrape.
        pagination_selector: CSS selector for next page link.
        check_robots: Whether to respect robots.txt.
        cookies: Optional cookies to include.

    Returns:
        ScrapePagesResult with extracted data.

    Examples:
        >>> from ciberwebscan.core.client import HTTPClient
        >>> result = scrape_static(
        ...     'https://example.com/products',
        ...     'div.product',
        ...     schema={'name': {'selector': '.title'}},
        ...     max_pages=5,
        ...     pagination_selector='a.next',
        ... )
    """
    # Create client if not provided
    if http_client is None:
        from ciberwebscan.core.client.http_client import HTTPClient

        http_client = HTTPClient()

    scraper = StaticScraper(http_client)

    config = ScrapeConfig(
        selector=selector,
        schema=schema,
        attributes=attributes,
        max_pages=max_pages,
        pagination_selector=pagination_selector,
        check_robots=check_robots,
        cookies=cookies,
    )

    return scraper.scrape_pages(url, config)
