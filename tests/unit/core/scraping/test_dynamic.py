"""
Unit tests for DynamicScraper.

Tests dynamic web scraping functionality including pagination,
proxy rotation, browser configuration, and structured extraction.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bs4 import BeautifulSoup

from ciberwebscan.core.scraping.dynamic import (
    BrowserType,
    DynamicScrapeConfig,
    DynamicScrapePagesResult,
    DynamicScraper,
    DynamicScrapeResult,
    WaitStrategy,
    scrape_dynamic_sync,
)


class TestBrowserType:
    """Tests for BrowserType enum."""

    def test_browser_types(self):
        """Test browser type values."""
        assert BrowserType.CHROMIUM.value == "chromium"
        assert BrowserType.FIREFOX.value == "firefox"
        assert BrowserType.WEBKIT.value == "webkit"


class TestWaitStrategy:
    """Tests for WaitStrategy enum."""

    def test_wait_strategies(self):
        """Test wait strategy values."""
        assert WaitStrategy.LOAD.value == "load"
        assert WaitStrategy.DOMCONTENTLOADED.value == "domcontentloaded"
        assert WaitStrategy.NETWORKIDLE.value == "networkidle"


class TestDynamicScrapeConfig:
    """Tests for DynamicScrapeConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = DynamicScrapeConfig(selector="div.item")

        assert config.selector == "div.item"
        assert config.wait_selector is None
        assert config.wait_timeout == 30.0
        assert config.wait_strategy == WaitStrategy.NETWORKIDLE
        assert config.pagination_selector is None
        assert config.max_pages == 1
        assert config.page_delay == 1.0
        assert config.browser_type == BrowserType.CHROMIUM
        assert config.headless is True
        assert config.viewport_width == 1920
        assert config.viewport_height == 1080
        assert config.cookies is None
        assert config.user_agent is None
        assert config.proxy is None
        assert config.check_robots is True
        assert config.allow_local is False
        assert config.attributes is None
        assert config.schema is None
        assert config.javascript_enabled is True
        assert config.scroll_to_bottom is False
        assert config.scroll_delay == 0.5
        assert config.block_resources is None

    def test_custom_values(self):
        """Test custom configuration."""
        config = DynamicScrapeConfig(
            selector="article",
            wait_selector=".loaded",
            wait_timeout=60.0,
            wait_strategy=WaitStrategy.LOAD,
            pagination_selector="a.next",
            max_pages=10,
            page_delay=2.0,
            browser_type=BrowserType.FIREFOX,
            headless=False,
            viewport_width=1280,
            viewport_height=720,
            cookies={"session": "abc"},
            user_agent="CustomBot/1.0",
            proxy="http://proxy:8080",
            check_robots=False,
            allow_local=True,
            schema={"title": {"selector": "h2"}},
            javascript_enabled=True,
            scroll_to_bottom=True,
            scroll_delay=1.0,
            block_resources=["image", "stylesheet"],
        )

        assert config.wait_selector == ".loaded"
        assert config.wait_timeout == 60.0
        assert config.wait_strategy == WaitStrategy.LOAD
        assert config.pagination_selector == "a.next"
        assert config.max_pages == 10
        assert config.browser_type == BrowserType.FIREFOX
        assert config.headless is False
        assert config.viewport_width == 1280
        assert config.cookies == {"session": "abc"}
        assert config.scroll_to_bottom is True
        assert config.block_resources == ["image", "stylesheet"]


class TestDynamicScrapeResult:
    """Tests for DynamicScrapeResult dataclass."""

    def test_default_values(self):
        """Test default result values."""
        result = DynamicScrapeResult(url="https://example.com", success=True)

        assert result.url == "https://example.com"
        assert result.success is True
        assert result.data == []
        assert result.html is None
        assert result.error is None
        assert result.page_number == 1
        assert result.elapsed_time == 0.0
        assert result.screenshot is None

    def test_success_result(self):
        """Test successful result with data."""
        result = DynamicScrapeResult(
            url="https://example.com",
            success=True,
            data=[{"id": 1}, {"id": 2}],
            html="<html></html>",
            elapsed_time=1.5,
        )

        assert result.success is True
        assert len(result.data) == 2
        assert result.html == "<html></html>"
        assert result.elapsed_time == 1.5

    def test_error_result(self):
        """Test error result."""
        result = DynamicScrapeResult(
            url="https://example.com",
            success=False,
            error="Browser timeout",
        )

        assert result.success is False
        assert result.error == "Browser timeout"


class TestDynamicScrapePagesResult:
    """Tests for DynamicScrapePagesResult dataclass."""

    def test_empty_result(self):
        """Test empty pages result."""
        result = DynamicScrapePagesResult()

        assert result.pages == []
        assert result.total_items == 0
        assert result.success is False
        assert result.all_data == []

    def test_combined_data(self):
        """Test combining data from multiple pages."""
        page1 = DynamicScrapeResult(
            url="https://example.com/1",
            success=True,
            data=[{"id": 1}, {"id": 2}],
        )
        page2 = DynamicScrapeResult(
            url="https://example.com/2",
            success=True,
            data=[{"id": 3}, {"id": 4}],
        )

        result = DynamicScrapePagesResult(pages=[page1, page2], total_items=4)

        assert result.success is True
        assert len(result.all_data) == 4
        assert result.all_data[0]["id"] == 1
        assert result.all_data[3]["id"] == 4

    def test_partial_success(self):
        """Test with some failed pages."""
        page1 = DynamicScrapeResult(url="url1", success=True, data=[{"id": 1}])
        page2 = DynamicScrapeResult(url="url2", success=False, error="Failed")

        result = DynamicScrapePagesResult(pages=[page1, page2], total_items=1)

        # Should still be success if at least one page succeeded
        assert result.success is True


def _create_mock_playwright(sample_html):
    """Create mock Playwright instance with all needed components."""
    mock_page = AsyncMock()
    mock_page.content = AsyncMock(return_value=sample_html)
    mock_page.goto = AsyncMock()
    mock_page.wait_for_selector = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value=1000)
    mock_page.route = AsyncMock()

    mock_context = AsyncMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_context.add_cookies = AsyncMock()
    mock_context.close = AsyncMock()

    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_browser.close = AsyncMock()

    mock_pw = MagicMock()
    mock_pw.chromium.launch = AsyncMock(return_value=mock_browser)
    mock_pw.firefox.launch = AsyncMock(return_value=mock_browser)
    mock_pw.webkit.launch = AsyncMock(return_value=mock_browser)
    mock_pw.stop = AsyncMock()

    return mock_pw, mock_browser, mock_context, mock_page


def _create_scraper_with_mocked_browser(mock_pw, **kwargs):
    """Create a DynamicScraper with mocked _start_browser."""
    scraper = DynamicScraper(**kwargs)

    async def mock_start_browser(
        browser_type: BrowserType = BrowserType.CHROMIUM,
        headless: bool = True,
    ):
        if browser_type == BrowserType.FIREFOX:
            browser = await mock_pw.firefox.launch(headless=headless)
        elif browser_type == BrowserType.WEBKIT:
            browser = await mock_pw.webkit.launch(headless=headless)
        else:
            browser = await mock_pw.chromium.launch(headless=headless)
        scraper._browser = browser
        scraper._playwright = mock_pw
        return browser

    scraper._start_browser = mock_start_browser
    return scraper


class TestDynamicScraper:
    """Tests for DynamicScraper class."""

    @pytest.fixture
    def sample_html(self):
        """Sample HTML for testing."""
        return """
        <html>
            <body>
                <div class="item">
                    <h2 class="title">Item 1</h2>
                    <span class="price">$10</span>
                </div>
                <div class="item">
                    <h2 class="title">Item 2</h2>
                    <span class="price">$20</span>
                </div>
                <a href="/page/2" class="next">Next</a>
            </body>
        </html>
        """

    def test_scrape_invalid_url(self):
        """Test scraping with invalid URL."""

        async def run_test():
            scraper = DynamicScraper()
            config = DynamicScrapeConfig(selector="div.item")
            return await scraper.scrape("not-a-url", config)

        result = asyncio.run(run_test())
        assert result.success is False
        assert result.error is not None and (
            "invalid" in result.error.lower() or "unsafe" in result.error.lower()
        )

    def test_scrape_success(self, sample_html):
        """Test successful single page scrape."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(selector="div.item", check_robots=False)

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True
        assert len(result.data) == 2
        assert result.html is not None
        assert result.elapsed_time > 0

    def test_scrape_with_schema(self, sample_html):
        """Test scraping with extraction schema."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                schema={
                    "name": {"selector": ".title"},
                    "cost": {"selector": ".price"},
                },
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True
        assert result.data[0]["name"] == "Item 1"
        assert result.data[0]["cost"] == "$10"

    def test_scrape_with_wait_selector(self, sample_html):
        """Test scraping with wait selector."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                wait_selector=".loaded",
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True

    def test_scrape_exception_handling(self, sample_html):
        """Test handling browser exceptions during page navigation."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )
        # Simulate an error during page navigation (after browser starts)
        mock_page.goto = AsyncMock(side_effect=Exception("Page navigation failed"))

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(selector="div.item", check_robots=False)

            return await scraper.scrape("https://example.com", config)

        result = asyncio.run(run_test())
        assert result.success is False
        assert result.error is not None and "Page navigation failed" in result.error

    def test_scrape_with_cookies_string(self, sample_html):
        """Test scraping with cookie string."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                cookies="session=abc; user=test",
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True

    def test_scrape_with_cookies_dict(self, sample_html):
        """Test scraping with cookie dictionary."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                cookies={"token": "xyz"},
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True

    def test_scrape_with_proxy(self, sample_html):
        """Test scraping with proxy configuration."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                proxy="http://proxy:8080",
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True

    def test_scrape_with_proxy_rotator(self, sample_html):
        """Test scraping with proxy rotation."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )
        mock_proxy_rotator = MagicMock()
        mock_proxy_rotator.next.return_value = "http://proxy:8080"

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(
                mock_pw, proxy_rotator=mock_proxy_rotator
            )
            config = DynamicScrapeConfig(
                selector="div.item",
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result, mock_proxy_rotator

        result, proxy_rotator = asyncio.run(run_test())
        assert result.success is True
        proxy_rotator.next.assert_called()

    def test_scrape_with_user_agent_provider(self, sample_html):
        """Test scraping with user agent provider."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )
        mock_ua_provider = MagicMock()
        mock_ua_provider.get.return_value = "CustomBot/1.0"

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(
                mock_pw, user_agent_provider=mock_ua_provider
            )
            config = DynamicScrapeConfig(
                selector="div.item",
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result, mock_ua_provider

        result, ua_provider = asyncio.run(run_test())
        assert result.success is True
        ua_provider.get.assert_called()

    def test_scrape_with_attributes(self):
        """Test scraping with specific attributes."""
        html = """
        <html>
            <a href="/link1" title="Link 1" class="item">First</a>
            <a href="/link2" title="Link 2" class="item">Second</a>
        </html>
        """
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(html)

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="a.item",
                attributes=["href", "title"],
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True
        assert result.data[0]["href"] == "/link1"
        assert result.data[0]["title"] == "Link 1"

    def test_scrape_pages_single(self, sample_html):
        """Test scraping single page."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                max_pages=1,
                check_robots=False,
            )

            result = await scraper.scrape_pages("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert len(result.pages) == 1
        assert result.total_items == 2

    def test_scrape_pages_max_limit(self):
        """Test max pages limit is respected."""
        page_html = """
        <html>
            <div class="item"><h2>Item</h2></div>
            <a href="/next" class="next">Next</a>
        </html>
        """
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            page_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                pagination_selector="a.next",
                max_pages=2,
                page_delay=0,
                check_robots=False,
            )

            result = await scraper.scrape_pages("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert len(result.pages) == 2

    def test_scrape_stops_on_same_url(self):
        """Test pagination stops when same URL is encountered."""
        html = """
        <html>
            <div class="item">Item</div>
            <a href="/page/1" class="next">Next</a>
        </html>
        """
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(html)

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                pagination_selector="a.next",
                max_pages=5,
                page_delay=0,
                check_robots=False,
            )

            result = await scraper.scrape_pages("https://example.com/page/1", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        # Should stop after first page due to same URL
        assert len(result.pages) == 1

    def test_context_manager(self, sample_html):
        """Test async context manager usage."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            async with scraper:
                config = DynamicScrapeConfig(
                    selector="div.item",
                    check_robots=False,
                )
                return await scraper.scrape("https://example.com", config)

        result = asyncio.run(run_test())
        assert result.success is True

    def test_different_browser_types(self, sample_html):
        """Test using different browser types."""
        for browser_type in [
            BrowserType.CHROMIUM,
            BrowserType.FIREFOX,
            BrowserType.WEBKIT,
        ]:
            mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
                sample_html
            )

            async def run_test(mock_pw=mock_pw, browser_type=browser_type):
                scraper = _create_scraper_with_mocked_browser(mock_pw)
                config = DynamicScrapeConfig(
                    selector="div.item",
                    browser_type=browser_type,
                    check_robots=False,
                )

                result = await scraper.scrape("https://example.com", config)
                await scraper._close_browser()
                return result

            result = asyncio.run(run_test())
            assert result.success is True

    def test_scrape_with_scroll_to_bottom(self, sample_html):
        """Test scraping with infinite scroll enabled."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                scroll_to_bottom=True,
                scroll_delay=0.01,
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True

    def test_scrape_with_block_resources(self, sample_html):
        """Test scraping with resource blocking."""
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                block_resources=["image", "stylesheet", "font"],
                check_robots=False,
            )

            result = await scraper.scrape("https://example.com", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True

    def test_prepare_cookies_none(self):
        """Test cookie preparation with None."""
        scraper = DynamicScraper()
        result = scraper._prepare_cookies(None)
        assert result is None

    def test_prepare_cookies_dict(self):
        """Test cookie preparation with dictionary."""
        scraper = DynamicScraper()
        cookies = {"session": "abc", "user": "test"}
        result = scraper._prepare_cookies(cookies)
        assert result == cookies

    def test_prepare_cookies_string(self):
        """Test cookie preparation with string."""
        scraper = DynamicScraper()
        result = scraper._prepare_cookies("session=abc; user=test")
        assert result == {"session": "abc", "user": "test"}

    def test_get_user_agent_default(self):
        """Test default user agent."""
        scraper = DynamicScraper()
        ua = scraper._get_user_agent()
        assert "Mozilla" in ua

    def test_get_user_agent_provider(self):
        """Test user agent from provider."""
        mock_provider = MagicMock()
        mock_provider.get.return_value = "CustomBot/1.0"

        scraper = DynamicScraper(user_agent_provider=mock_provider)
        ua = scraper._get_user_agent()
        assert ua == "CustomBot/1.0"

    def test_get_proxy_none(self):
        """Test proxy when no rotator is configured."""
        scraper = DynamicScraper()
        proxy = scraper._get_proxy()
        assert proxy is None

    def test_get_proxy_with_rotator(self):
        """Test proxy from rotator."""
        mock_rotator = MagicMock()
        mock_rotator.next.return_value = "http://proxy:8080"

        scraper = DynamicScraper(proxy_rotator=mock_rotator)
        proxy = scraper._get_proxy()
        assert proxy == "http://proxy:8080"

    def test_extract_data_with_schema(self):
        """Test data extraction with schema."""
        html = """
        <div class="item">
            <h2 class="title">Test Item</h2>
            <span class="price">$99</span>
        </div>
        """
        soup = BeautifulSoup(html, "html.parser")

        scraper = DynamicScraper()
        config = DynamicScrapeConfig(
            selector="div.item",
            schema={
                "name": {"selector": ".title"},
                "cost": {"selector": ".price"},
            },
        )

        data = scraper._extract_data(soup, config)

        assert len(data) == 1
        assert data[0]["name"] == "Test Item"
        assert data[0]["cost"] == "$99"

    def test_extract_data_with_attributes(self):
        """Test data extraction with attributes."""
        html = """
        <a href="/link" title="Test Link" class="item">Click</a>
        """
        soup = BeautifulSoup(html, "html.parser")

        scraper = DynamicScraper()
        config = DynamicScrapeConfig(
            selector="a.item",
            attributes=["href", "title"],
        )

        data = scraper._extract_data(soup, config)

        assert len(data) == 1
        assert data[0]["href"] == "/link"
        assert data[0]["title"] == "Test Link"

    def test_extract_data_default(self):
        """Test default data extraction."""
        html = """
        <div class="item">Test Content</div>
        """
        soup = BeautifulSoup(html, "html.parser")

        scraper = DynamicScraper()
        config = DynamicScrapeConfig(selector="div.item")

        data = scraper._extract_data(soup, config)

        assert len(data) == 1
        assert data[0]["text"] == "Test Content"


class TestScrapeDynamicSyncFunction:
    """Tests for scrape_dynamic_sync convenience function."""

    def test_sync_wrapper(self):
        """Test synchronous wrapper."""
        # For sync wrapper, we need to patch the DynamicScraper class used internally
        with patch(
            "ciberwebscan.core.scraping.dynamic.DynamicScraper"
        ) as mock_scraper_cls:
            # Create mock result
            mock_result = DynamicScrapePagesResult(
                pages=[
                    DynamicScrapeResult(
                        url="https://example.com",
                        success=True,
                        data=[{"text": "Test"}],
                    )
                ],
                total_items=1,
            )

            # Create mock scraper instance with async context manager support
            mock_scraper = MagicMock()
            mock_scraper.__aenter__ = AsyncMock(return_value=mock_scraper)
            mock_scraper.__aexit__ = AsyncMock(return_value=None)
            mock_scraper.scrape_pages = AsyncMock(return_value=mock_result)

            mock_scraper_cls.return_value = mock_scraper

            result = scrape_dynamic_sync(
                "https://example.com",
                "div.item",
                check_robots=False,
            )

            assert result.success is True
            assert result.total_items == 1


class TestRobotsIntegration:
    """Tests for robots.txt integration."""

    def test_robots_blocks_scraping(self):
        """Test that robots.txt blocking stops scraping."""

        async def run_test():
            with patch(
                "ciberwebscan.core.scraping.dynamic.check_robots_txt"
            ) as mock_robots:
                mock_robots.return_value = (False, "Blocked by robots.txt")

                scraper = DynamicScraper()
                config = DynamicScrapeConfig(selector="div.item", check_robots=True)
                return await scraper.scrape("https://example.com/page", config)

        result = asyncio.run(run_test())
        assert result.success is False
        assert result.error is not None
        assert "robots" in result.error.lower()

    def test_robots_disabled(self):
        """Test scraping with robots.txt check disabled."""
        sample_html = "<div class='item'>Test</div>"
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(selector="div.item", check_robots=False)
            result = await scraper.scrape("https://example.com/page", config)
            await scraper._close_browser()
            return result

        result = asyncio.run(run_test())
        assert result.success is True


class TestBrowserContext:
    """Tests for browser context configuration."""

    def test_viewport_configuration(self):
        """Test viewport configuration is applied."""
        sample_html = "<div class='item'>Test</div>"
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                viewport_width=1280,
                viewport_height=720,
                check_robots=False,
            )

            await scraper.scrape("https://example.com", config)

            # Verify viewport was passed to new_context
            call_kwargs = mock_browser.new_context.call_args[1]
            await scraper._close_browser()
            return call_kwargs

        call_kwargs = asyncio.run(run_test())
        assert call_kwargs["viewport"]["width"] == 1280
        assert call_kwargs["viewport"]["height"] == 720

    def test_javascript_disabled(self):
        """Test JavaScript can be disabled."""
        sample_html = "<div class='item'>Test</div>"
        mock_pw, mock_browser, mock_context, mock_page = _create_mock_playwright(
            sample_html
        )

        async def run_test():
            scraper = _create_scraper_with_mocked_browser(mock_pw)
            config = DynamicScrapeConfig(
                selector="div.item",
                javascript_enabled=False,
                check_robots=False,
            )

            await scraper.scrape("https://example.com", config)

            call_kwargs = mock_browser.new_context.call_args[1]
            await scraper._close_browser()
            return call_kwargs

        call_kwargs = asyncio.run(run_test())
        assert call_kwargs["java_script_enabled"] is False
