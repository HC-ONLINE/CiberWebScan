"""
Core scraping module.

Provides static and dynamic web scraping capabilities with
structured data extraction, pagination support, and robots.txt compliance.

Static Scraping:
    Use `StaticScraper` for pages that don't require JavaScript.
    This is faster and uses less resources.

Dynamic Scraping:
    Use `DynamicScraper` for JavaScript-rendered pages.
    Requires Playwright: `pip install playwright && playwright install`

Examples:
    Static scraping::

        from ciberwebscan.core.client import HTTPClient
        from ciberwebscan.core.scraping import StaticScraper, ScrapeConfig

        client = HTTPClient()
        scraper = StaticScraper(client)

        config = ScrapeConfig(
            selector='div.product',
            schema={'name': {'selector': '.title'}, 'price': {'selector': '.price'}},
            max_pages=5,
            pagination_selector='a.next',
        )

        result = scraper.scrape_pages('https://example.com/products', config)
        for item in result.all_data:
            print(item)

    Dynamic scraping::

        from ciberwebscan.core.scraping import DynamicScraper, DynamicScrapeConfig

        async def scrape_spa():
            async with DynamicScraper() as scraper:
                config = DynamicScrapeConfig(
                    selector='div.item',
                    wait_selector='.content-loaded',
                    schema={'title': {'selector': 'h2'}},
                )
                result = await scraper.scrape('https://spa.example.com', config)
                return result.data

    Data extraction::

        from bs4 import BeautifulSoup
        from ciberwebscan.core.scraping import DataExtractor

        html = '<div><h2>Title</h2><span class="price">$19.99</span></div>'
        soup = BeautifulSoup(html, 'html.parser')

        extractor = DataExtractor()
        data = extractor.extract(soup.div, {
            'title': {'selector': 'h2'},
            'price': {'selector': '.price'},
        })
"""

from typing import TYPE_CHECKING, Any

from .extractor import (
    DataExtractor,
    ExtractionSchema,
    FieldConfig,
    extract_images,
    extract_links,
    extract_structured,
    extract_table,
)
from .helpers import (
    check_robots_txt,
    extract_attribute,
    extract_text,
    find_next_page_url,
    is_safe_url,
    parse_cookie_string,
    parse_set_cookie_headers,
    process_elements,
)
from .static import (
    ScrapeConfig,
    ScrapePagesResult,
    ScrapeResult,
    StaticScraper,
    scrape_static,
)

if TYPE_CHECKING:
    from .dynamic import (
        BrowserType,
        DynamicScrapeConfig,
        DynamicScrapePagesResult,
        DynamicScraper,
        DynamicScrapeResult,
        WaitStrategy,
        scrape_dynamic,
        scrape_dynamic_sync,
    )

# Dynamic scraper imports (optional - requires playwright)
try:
    from .dynamic import (
        BrowserType,
        DynamicScrapeConfig,
        DynamicScrapePagesResult,
        DynamicScraper,
        DynamicScrapeResult,
        WaitStrategy,
        scrape_dynamic,
        scrape_dynamic_sync,
    )

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

    # Set to None when not available - users should check is_playwright_available()
    BrowserType: Any = None
    DynamicScrapeConfig: Any = None
    DynamicScrapePagesResult: Any = None
    DynamicScrapeResult: Any = None
    DynamicScraper: Any = None
    WaitStrategy: Any = None
    scrape_dynamic: Any = None
    scrape_dynamic_sync: Any = None


def is_playwright_available() -> bool:
    """
    Check if Playwright is available for dynamic scraping.

    Returns:
        True if playwright is installed, False otherwise.
    """
    return _PLAYWRIGHT_AVAILABLE


__all__ = [
    # Helpers
    "is_safe_url",
    "check_robots_txt",
    "find_next_page_url",
    "parse_cookie_string",
    "parse_set_cookie_headers",
    "extract_text",
    "extract_attribute",
    "process_elements",
    # Extractor
    "DataExtractor",
    "ExtractionSchema",
    "FieldConfig",
    "extract_structured",
    "extract_table",
    "extract_links",
    "extract_images",
    # Static scraper
    "StaticScraper",
    "ScrapeConfig",
    "ScrapeResult",
    "ScrapePagesResult",
    "scrape_static",
    # Dynamic scraper
    "DynamicScraper",
    "DynamicScrapeConfig",
    "DynamicScrapeResult",
    "DynamicScrapePagesResult",
    "BrowserType",
    "WaitStrategy",
    "scrape_dynamic",
    "scrape_dynamic_sync",
    "is_playwright_available",
]
