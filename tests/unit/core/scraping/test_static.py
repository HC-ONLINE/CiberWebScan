"""
Unit tests for StaticScraper.

Tests static web scraping functionality including pagination,
proxy rotation, and structured extraction.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ciberwebscan.core.scraping.static import (
    ScrapeConfig,
    ScrapePagesResult,
    ScrapeResult,
    StaticScraper,
    scrape_static,
)


class TestScrapeConfig:
    """Tests for ScrapeConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScrapeConfig(selector="div.item")

        assert config.selector == "div.item"
        assert config.pagination_selector is None
        assert config.max_pages == 1
        assert config.page_delay == 1.0
        assert config.timeout == 30.0
        assert config.verify_ssl is True
        assert config.check_robots is True
        assert config.allow_local is False

    def test_custom_values(self):
        """Test custom configuration."""
        config = ScrapeConfig(
            selector="article",
            pagination_selector="a.next",
            max_pages=10,
            page_delay=2.0,
            cookies={"session": "abc"},
            schema={"title": {"selector": "h2"}},
        )

        assert config.pagination_selector == "a.next"
        assert config.max_pages == 10
        assert config.cookies == {"session": "abc"}


class TestScrapeResult:
    """Tests for ScrapeResult dataclass."""

    def test_default_values(self):
        """Test default result values."""
        result = ScrapeResult(url="https://example.com", success=True)

        assert result.url == "https://example.com"
        assert result.success is True
        assert result.status_code is None
        assert result.data == []
        assert result.error is None
        assert result.page_number == 1

    def test_error_result(self):
        """Test error result."""
        result = ScrapeResult(
            url="https://example.com",
            success=False,
            error="Connection timeout",
        )

        assert result.success is False
        assert result.error == "Connection timeout"


class TestScrapePagesResult:
    """Tests for ScrapePagesResult dataclass."""

    def test_empty_result(self):
        """Test empty pages result."""
        result = ScrapePagesResult()

        assert result.pages == []
        assert result.total_items == 0
        assert result.success is False
        assert result.all_data == []

    def test_combined_data(self):
        """Test combining data from multiple pages."""
        page1 = ScrapeResult(
            url="https://example.com/1",
            success=True,
            data=[{"id": 1}, {"id": 2}],
        )
        page2 = ScrapeResult(
            url="https://example.com/2",
            success=True,
            data=[{"id": 3}, {"id": 4}],
        )

        result = ScrapePagesResult(pages=[page1, page2], total_items=4)

        assert result.success is True
        assert len(result.all_data) == 4
        assert result.all_data[0]["id"] == 1
        assert result.all_data[3]["id"] == 4

    def test_partial_success(self):
        """Test with some failed pages."""
        page1 = ScrapeResult(url="url1", success=True, data=[{"id": 1}])
        page2 = ScrapeResult(url="url2", success=False, error="Failed")

        result = ScrapePagesResult(pages=[page1, page2], total_items=1)

        # Should still be success if at least one page succeeded
        assert result.success is True


class TestStaticScraper:
    """Tests for StaticScraper class."""

    @pytest.fixture
    def mock_client(self):
        """Create mock HTTP client."""
        return MagicMock()

    @pytest.fixture
    def scraper(self, mock_client):
        """Create scraper instance with mock client."""
        return StaticScraper(mock_client)

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

    def test_scrape_success(self, scraper, mock_client, sample_html):
        """Test successful single page scrape."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = sample_html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(selector="div.item", check_robots=False)
        result = scraper.scrape("https://example.com", config)

        assert result.success is True
        assert result.status_code == 200
        assert len(result.data) == 2

    def test_scrape_with_schema(self, scraper, mock_client, sample_html):
        """Test scraping with extraction schema."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = sample_html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(
            selector="div.item",
            schema={
                "name": {"selector": ".title"},
                "cost": {"selector": ".price"},
            },
            check_robots=False,
        )
        result = scraper.scrape("https://example.com", config)

        assert result.success is True
        assert result.data[0]["name"] == "Item 1"
        assert result.data[0]["cost"] == "$10"

    def test_scrape_invalid_url(self, scraper):
        """Test scraping with invalid URL."""
        config = ScrapeConfig(selector="div.item")
        result = scraper.scrape("not-a-url", config)

        assert result.success is False
        assert "invalid" in result.error.lower() or "unsafe" in result.error.lower()

    def test_scrape_http_error(self, scraper, mock_client):
        """Test handling HTTP errors."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(selector="div.item", check_robots=False)
        result = scraper.scrape("https://example.com", config)

        assert result.success is False
        assert result.status_code == 404
        assert "404" in result.error

    def test_scrape_request_exception(self, scraper, mock_client):
        """Test handling request exceptions."""
        mock_client.get.side_effect = Exception("Connection failed")

        config = ScrapeConfig(selector="div.item", check_robots=False)
        result = scraper.scrape("https://example.com", config)

        assert result.success is False
        assert "Connection failed" in result.error

    def test_scrape_with_cookies_string(self, scraper, mock_client, sample_html):
        """Test scraping with cookie string."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = sample_html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(
            selector="div.item",
            cookies="session=abc; user=test",
            check_robots=False,
        )
        scraper.scrape("https://example.com", config)

        # Verify cookies were passed
        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["cookies"] == {"session": "abc", "user": "test"}

    def test_scrape_with_cookies_dict(self, scraper, mock_client, sample_html):
        """Test scraping with cookie dictionary."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = sample_html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(
            selector="div.item",
            cookies={"token": "xyz"},
            check_robots=False,
        )
        scraper.scrape("https://example.com", config)

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["cookies"] == {"token": "xyz"}

    def test_scrape_pages_single(self, scraper, mock_client, sample_html):
        """Test scraping single page."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = sample_html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(
            selector="div.item",
            max_pages=1,
            check_robots=False,
        )
        result = scraper.scrape_pages("https://example.com", config)

        assert len(result.pages) == 1
        assert result.total_items == 2

    def test_scrape_pages_pagination(self, scraper, mock_client):
        """Test scraping with pagination."""
        page1_html = """
        <html>
            <div class="item"><h2>Item 1</h2></div>
            <a href="/page/2" class="next">Next</a>
        </html>
        """
        page2_html = """
        <html>
            <div class="item"><h2>Item 2</h2></div>
        </html>
        """

        mock_response1 = MagicMock()
        mock_response1.status_code = 200
        mock_response1.text = page1_html

        mock_response2 = MagicMock()
        mock_response2.status_code = 200
        mock_response2.text = page2_html

        mock_client.get.side_effect = [mock_response1, mock_response2]

        config = ScrapeConfig(
            selector="div.item",
            pagination_selector="a.next",
            max_pages=3,
            page_delay=0,  # No delay for testing
            check_robots=False,
        )
        result = scraper.scrape_pages("https://example.com", config)

        assert len(result.pages) == 2
        assert result.pages[0].page_number == 1
        assert result.pages[1].page_number == 2

    def test_scrape_pages_max_limit(self, scraper, mock_client):
        """Test max pages limit is respected."""
        page_html = """
        <html>
            <div class="item"><h2>Item</h2></div>
            <a href="/next" class="next">Next</a>
        </html>
        """

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = page_html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(
            selector="div.item",
            pagination_selector="a.next",
            max_pages=2,
            page_delay=0,
            check_robots=False,
        )
        result = scraper.scrape_pages("https://example.com", config)

        assert len(result.pages) == 2

    def test_scrape_with_user_agent_provider(self, mock_client):
        """Test scraping with user agent provider."""
        mock_ua_provider = MagicMock()
        mock_ua_provider.get.return_value = "CustomBot/1.0"

        scraper = StaticScraper(mock_client, user_agent_provider=mock_ua_provider)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<div class='item'>Test</div>"
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(selector="div.item", check_robots=False)
        scraper.scrape("https://example.com", config)

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["headers"]["User-Agent"] == "CustomBot/1.0"

    def test_scrape_with_attributes(self, scraper, mock_client):
        """Test scraping with specific attributes."""
        html = """
        <html>
            <a href="/link1" title="Link 1" class="item">First</a>
            <a href="/link2" title="Link 2" class="item">Second</a>
        </html>
        """

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(
            selector="a.item",
            attributes=["href", "title"],
            check_robots=False,
        )
        result = scraper.scrape("https://example.com", config)

        assert result.data[0]["href"] == "/link1"
        assert result.data[0]["title"] == "Link 1"

    def test_scrape_stops_on_same_url(self, scraper, mock_client):
        """Test pagination stops when same URL is encountered."""
        html = """
        <html>
            <div class="item">Item</div>
            <a href="/page/1" class="next">Next</a>
        </html>
        """

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = html
        mock_client.get.return_value = mock_response

        config = ScrapeConfig(
            selector="div.item",
            pagination_selector="a.next",
            max_pages=5,
            page_delay=0,
            check_robots=False,
        )

        # Mock the same URL being returned (circular)
        result = scraper.scrape_pages("https://example.com/page/1", config)

        # Should stop after first page due to same URL
        assert len(result.pages) == 1


class TestScrapeStaticFunction:
    """Tests for scrape_static convenience function."""

    def test_basic_usage(self):
        """Test basic usage with mock client."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<div class='item'>Test</div>"
        mock_client.get.return_value = mock_response

        result = scrape_static(
            "https://example.com",
            "div.item",
            http_client=mock_client,
            check_robots=False,
        )

        assert result.success is True
        assert len(result.all_data) == 1

    def test_with_schema(self):
        """Test with extraction schema."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <div class='product'>
            <span class='name'>Widget</span>
            <span class='price'>$10</span>
        </div>
        """
        mock_client.get.return_value = mock_response

        result = scrape_static(
            "https://example.com",
            "div.product",
            http_client=mock_client,
            schema={
                "name": {"selector": ".name"},
                "price": {"selector": ".price"},
            },
            check_robots=False,
        )

        assert result.all_data[0]["name"] == "Widget"
        assert result.all_data[0]["price"] == "$10"


class TestRobotsIntegration:
    """Tests for robots.txt integration."""

    def test_robots_blocks_scraping(self):
        """Test that robots.txt blocking stops scraping."""
        mock_client = MagicMock()

        # robots.txt disallows
        robots_response = MagicMock()
        robots_response.status_code = 200
        robots_response.text = "User-agent: *\nDisallow: /"
        mock_client.get.return_value = robots_response

        scraper = StaticScraper(mock_client)
        config = ScrapeConfig(selector="div.item", check_robots=True)
        result = scraper.scrape("https://example.com/page", config)

        assert result.success is False
        assert result.error is not None and "robots" in result.error.lower()

    def test_robots_disabled(self):
        """Test scraping with robots.txt check disabled."""
        mock_client = MagicMock()

        page_response = MagicMock()
        page_response.status_code = 200
        page_response.text = "<div class='item'>Test</div>"
        mock_client.get.return_value = page_response

        scraper = StaticScraper(mock_client)
        config = ScrapeConfig(selector="div.item", check_robots=False)
        result = scraper.scrape("https://example.com/page", config)

        assert result.success is True
