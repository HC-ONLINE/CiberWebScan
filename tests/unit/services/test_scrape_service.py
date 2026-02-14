"""
Tests for ScrapeService class.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ciberwebscan.export.models import ScrapeResult
from ciberwebscan.services.base import ServiceResult
from ciberwebscan.services.scrape_service import (
    ScrapeOptions,
    ScrapeService,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def scrape_service() -> ScrapeService:
    """Create a test scrape service."""
    return ScrapeService()


@pytest.fixture
def mock_scrape_result() -> ScrapeResult:
    """Create a mock scrape result."""
    return ScrapeResult(
        url="https://example.com",
        status_code=200,
        content_type="text/html",
        title="Example Domain",
        text_content="<html><head><title>Example</title></head><body>Hello</body></html>",
        headers={"content-type": "text/html"},
        elapsed_ms=100.0,
    )


# =============================================================================
# ScrapeOptions Tests
# =============================================================================


class TestScrapeOptions:
    """Tests for ScrapeOptions dataclass."""

    def test_default_options(self):
        """Test default option values."""
        options = ScrapeOptions(url="https://example.com")

        assert options.url == "https://example.com"
        assert options.dynamic is False
        assert options.timeout == 30.0
        assert options.selector is None
        assert options.export is None
        assert options.export_format == "json"

    def test_custom_options(self):
        """Test custom option values."""
        options = ScrapeOptions(
            url="https://example.com",
            dynamic=True,
            timeout=60.0,
            selector="div.content",
            export="output.json",
            export_format="jsonl",
            headers={"Accept": "text/html"},
        )

        assert options.dynamic is True
        assert options.timeout == 60.0
        assert options.selector == "div.content"
        assert options.export == "output.json"
        assert options.export_format == "jsonl"
        assert "Accept" in options.headers


# =============================================================================
# ScrapeService Tests
# =============================================================================


class TestScrapeService:
    """Tests for ScrapeService class."""

    def test_service_creation(self, scrape_service: ScrapeService):
        """Test service instantiation."""
        assert scrape_service is not None
        assert scrape_service.config is not None

    def test_service_with_custom_config(self):
        """Test service with custom configuration."""
        from ciberwebscan.config.models import ScrapingConfig

        config = ScrapingConfig(extract_links=False)
        service = ScrapeService(config=config)

        assert service.config.extract_links is False

    @patch.object(ScrapeService, "_scrape_static")
    def test_scrape_static_success(
        self,
        mock_scrape: Mock,
        scrape_service: ScrapeService,
        mock_scrape_result: ScrapeResult,
    ):
        """Test successful static scraping."""
        mock_scrape.return_value = mock_scrape_result

        options = ScrapeOptions(url="https://example.com")
        result = scrape_service.scrape(options)

        assert result.success is True
        assert result.data is not None
        mock_scrape.assert_called_once()

    @patch.object(ScrapeService, "_scrape_static")
    def test_scrape_with_export(
        self,
        mock_scrape: Mock,
        scrape_service: ScrapeService,
        mock_scrape_result: ScrapeResult,
        tmp_path: Path,
    ):
        """Test scraping with export."""
        mock_scrape.return_value = mock_scrape_result
        output_file = tmp_path / "output.json"

        options = ScrapeOptions(
            url="https://example.com",
            export=str(output_file),
            export_format="json",
        )
        result = scrape_service.scrape(options)

        assert result.success is True
        assert result.exported is True
        assert result.export_path is not None

    def test_scrape_invalid_url(self, scrape_service: ScrapeService):
        """Test scraping with invalid URL."""
        options = ScrapeOptions(url="")
        result = scrape_service.scrape(options)

        assert result.success is False
        assert result.error_code == "VALIDATION_ERROR"

    @patch.object(ScrapeService, "_scrape_static")
    def test_scrape_with_selector(
        self,
        mock_scrape: Mock,
        scrape_service: ScrapeService,
        mock_scrape_result: ScrapeResult,
    ):
        """Test scraping with CSS selector."""
        mock_scrape.return_value = mock_scrape_result

        with patch.object(scrape_service, "_extract_data") as mock_extract:
            mock_extract.return_value = [{"text": "Hello"}]

            options = ScrapeOptions(
                url="https://example.com",
                selector="div.content",
            )
            result = scrape_service.scrape(options)

            assert result.success is True
            mock_extract.assert_called_once()

    def test_scrape_dynamic_not_available(self, scrape_service: ScrapeService):
        """Test dynamic scraping when playwright not available."""
        with patch(
            "ciberwebscan.services.scrape_service.is_playwright_available",
            return_value=False,
        ):
            options = ScrapeOptions(url="https://example.com", dynamic=True)
            result = scrape_service.scrape(options)

            assert result.success is False
            assert "playwright" in result.error.lower()

    @patch("ciberwebscan.core.client.HTTPClient")
    @patch("ciberwebscan.services.scrape_service.get_config")
    def test_static_scraper_uses_http_config(
        self,
        mock_get_config: Mock,
        mock_http_client: Mock,
    ):
        """Test static scraper builds HTTP client from global config."""
        http_config = Mock(
            timeout=Mock(read=45.0),
            retry=Mock(max_attempts=4, backoff_factor=0.7),
            rate_limit=Mock(requests_per_second=3.0, per_domain=True),
            http2=False,
            verify_ssl=False,
            follow_redirects=False,
        )
        mock_get_config.return_value = Mock(scraping=Mock(), http=http_config)

        service = ScrapeService()
        _ = service.static_scraper

        mock_http_client.assert_called_once_with(
            timeout=45.0,
            max_retries=4,
            backoff_factor=0.7,
            rate_limit=3.0,
            http2=False,
            verify=False,
            follow_redirects=False,
            proxy=None,
        )


# =============================================================================
# Multiple URL Tests
# =============================================================================


class TestScrapeMultiple:
    """Tests for scraping multiple URLs."""

    @patch.object(ScrapeService, "scrape")
    def test_scrape_multiple_success(
        self,
        mock_scrape: Mock,
        scrape_service: ScrapeService,
    ):
        """Test scraping multiple URLs successfully."""
        mock_result = ServiceResult[ScrapeResult](
            success=True,
            data=ScrapeResult(
                url="https://example.com",
                status_code=200,
                content_type="text/html",
                title="Test",
                text_content="",
                headers={},
                elapsed_ms=50.0,
            ),
        )
        mock_scrape.return_value = mock_result

        urls = [
            "https://example.com/page1",
            "https://example.com/page2",
        ]
        options = ScrapeOptions(url="")

        result = scrape_service.scrape_multiple(urls, options)

        assert result.success is True
        assert len(result.data) == 2

    @patch.object(ScrapeService, "scrape")
    def test_scrape_multiple_partial_failure(
        self,
        mock_scrape: Mock,
        scrape_service: ScrapeService,
    ):
        """Test scraping with some failures."""
        success_result = ServiceResult[ScrapeResult](
            success=True,
            data=ScrapeResult(
                url="https://example.com",
                status_code=200,
                content_type="text/html",
                title="Test",
                text_content="",
                headers={},
                elapsed_ms=50.0,
            ),
        )
        fail_result = ServiceResult[ScrapeResult](
            success=False,
            error="Connection failed",
        )

        mock_scrape.side_effect = [success_result, fail_result]

        urls = ["https://example.com/page1", "https://fail.com"]
        options = ScrapeOptions(url="")

        result = scrape_service.scrape_multiple(urls, options)

        assert result.success is True  # At least one succeeded
        assert len(result.data) == 1
        assert len(result.warnings) == 1


# =============================================================================
# Context Manager Tests
# =============================================================================


class TestScrapeServiceContextManager:
    """Tests for context manager functionality."""

    def test_context_manager_enter_exit(self):
        """Test using service as context manager."""
        with ScrapeService() as service:
            assert service is not None

    def test_close_cleans_resources(self, scrape_service: ScrapeService):
        """Test close method."""
        scrape_service._dynamic_scraper = Mock()
        scrape_service.close()

        assert scrape_service._dynamic_scraper is None
