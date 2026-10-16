"""
Tests for ScrapeService class.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ciberwebscan.core.scraping.dynamic import DynamicScrapeResult
from ciberwebscan.export.models import ScrapeResult
from ciberwebscan.services.base import ServiceResult
from ciberwebscan.services.scrape_service import (
    ScrapeOptions,
    ScrapeService,
)

pytestmark = pytest.mark.unit

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def scrape_service() -> ScrapeService:
    """Create a test scrape service."""
    return ScrapeService()


@pytest.fixture(autouse=True)
def mock_export_path_validation():
    """Mock path validation for export operations in tests."""
    with patch(
        "ciberwebscan.services.base.resolve_and_validate_path",
        side_effect=lambda p, base, **kw: (
            Path(p) if Path(p).is_absolute() else (base / p).resolve()
        ),
    ):
        yield


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


def _mock_http_response(
    status: int, text: str = "<html><body>ok</body></html>"
) -> Mock:
    """Build a minimal HTTP response stub for StaticScraper."""
    response = Mock()
    response.status_code = status
    response.headers = {"content-type": "text/html"}
    response.text = text
    response.cookies.items.return_value = {}
    return response


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
            proxy=None,
        )
        mock_get_config.return_value = Mock(
            scraping=Mock(allow_local=False),
            http=http_config,
            user_agent=Mock(
                mode="static", custom="TestAgent", rotate_interval=1, agents=None
            ),
        )

        service = ScrapeService()
        _ = service.static_scraper

        mock_http_client.assert_called_once_with(
            timeout=45.0,
            max_attempts=4,
            backoff_factor=0.7,
            rate_limit=3.0,
            http2=False,
            verify=False,
            follow_redirects=False,
            cookies=None,
            proxy=None,
            default_headers={"User-Agent": "TestAgent"},
            ssrf_guard=True,
            allow_local=False,
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
# Dynamic Scraping Config Defaults Tests
# =============================================================================


class TestScrapeDynamicConfigDefaults:
    """Tests that _scrape_dynamic applies DynamicScrapingConfig defaults."""

    def _run_dynamic(
        self,
        scrape_service: ScrapeService,
        options: ScrapeOptions,
        mock_dsc: Mock,
        mock_bt: Mock,
    ) -> None:
        """Helper: run _scrape_dynamic with asyncio fully mocked."""
        mock_result = Mock(
            html="<html/>",
            status_code=200,
            elapsed_time=0.1,
            title="",
            links=[],
            images=[],
            forms=[],
            scripts=[],
        )
        scrape_service._dynamic_scraper = Mock()
        scrape_service._dynamic_scraper.scrape = Mock(return_value=mock_result)

        # mock_dsc returns a fake config object; mock_bt returns a dummy enum
        mock_dsc.return_value = Mock()
        mock_bt.side_effect = lambda v: Mock(value=v)

        with patch(
            "ciberwebscan.services.scrape_service.run_async",
            return_value=mock_result,
        ):
            scrape_service._scrape_dynamic("https://example.com", options)

    @patch(
        "ciberwebscan.services.scrape_service.is_playwright_available",
        return_value=True,
    )
    @patch("ciberwebscan.core.scraping.BrowserType")
    @patch("ciberwebscan.core.scraping.DynamicScrapeConfig")
    def test_config_headless_browser_timeout_applied(
        self,
        mock_dsc: Mock,
        mock_bt: Mock,
        _mock_avail: Mock,
        scrape_service: ScrapeService,
    ):
        """headless, browser_type y wait_timeout se toman de config.dynamic."""
        from ciberwebscan.config.models import DynamicScrapingConfig

        scrape_service.config.dynamic = DynamicScrapingConfig(
            enabled=True,
            headless=False,
            browser_type="firefox",
            wait_timeout=45.0,
        )

        self._run_dynamic(
            scrape_service,
            ScrapeOptions(url="https://example.com"),
            mock_dsc,
            mock_bt,
        )

        _, kwargs = mock_dsc.call_args
        assert kwargs["headless"] is False
        assert kwargs["wait_timeout"] == 45.0
        mock_bt.assert_called_with("firefox")

    @patch(
        "ciberwebscan.services.scrape_service.is_playwright_available",
        return_value=True,
    )
    @patch("ciberwebscan.core.scraping.BrowserType")
    @patch("ciberwebscan.core.scraping.DynamicScrapeConfig")
    def test_options_wait_for_overrides_config_wait_selector(
        self,
        mock_dsc: Mock,
        mock_bt: Mock,
        _mock_avail: Mock,
        scrape_service: ScrapeService,
    ):
        """options.wait_for tiene prioridad sobre config.dynamic.wait_selector."""
        from ciberwebscan.config.models import DynamicScrapingConfig

        scrape_service.config.dynamic = DynamicScrapingConfig(
            enabled=True,
            wait_selector=".config-default",
        )

        self._run_dynamic(
            scrape_service,
            ScrapeOptions(url="https://example.com", wait_for=".options-override"),
            mock_dsc,
            mock_bt,
        )

        _, kwargs = mock_dsc.call_args
        assert kwargs["wait_selector"] == ".options-override"

    @patch(
        "ciberwebscan.services.scrape_service.is_playwright_available",
        return_value=True,
    )
    @patch("ciberwebscan.core.scraping.BrowserType")
    @patch("ciberwebscan.core.scraping.DynamicScrapeConfig")
    def test_config_wait_selector_used_when_options_wait_for_is_none(
        self,
        mock_dsc: Mock,
        mock_bt: Mock,
        _mock_avail: Mock,
        scrape_service: ScrapeService,
    ):
        """config.dynamic.wait_selector se usa cuando options.wait_for es None."""
        from ciberwebscan.config.models import DynamicScrapingConfig

        scrape_service.config.dynamic = DynamicScrapingConfig(
            enabled=True,
            wait_selector=".from-config",
        )

        self._run_dynamic(
            scrape_service,
            ScrapeOptions(url="https://example.com", wait_for=None),
            mock_dsc,
            mock_bt,
        )

        _, kwargs = mock_dsc.call_args
        assert kwargs["wait_selector"] == ".from-config"


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


# =============================================================================
# Failure Propagation Tests (BUG-005)
# =============================================================================


class TestScrapeFailurePropagation:
    """Core scraping failures must surface as service failures.

    These tests cross the real core/service boundary: the real
    ``StaticScraper`` runs against a mocked ``HTTPClient`` so that
    ``success=False`` results produced by the engine actually reach
    ``ScrapeService`` (regression for BUG-005).
    """

    def test_static_http_200_still_succeeds(self):
        """HTTP 200 keeps producing a successful service result."""
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(200)
            service = ScrapeService()
            result = service.scrape(
                ScrapeOptions(url="https://example.com", check_robots=False)
            )
            service.close()

        assert result.success is True
        assert result.error is None
        assert isinstance(result.data, ScrapeResult)
        assert result.data.status_code == 200

    def test_static_http_404_propagates_failure(self):
        """Engine failure for HTTP 404 must not become a service success."""
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(
                404, "<html>Not Found</html>"
            )
            service = ScrapeService()
            result = service.scrape(
                ScrapeOptions(url="https://example.com/missing", check_robots=False)
            )
            service.close()

        assert result.success is False
        assert "404" in (result.error or "")
        assert result.error_code == "EXECUTION_ERROR"
        assert result.data is None

    def test_static_connection_error_propagates_failure(self):
        """Connection errors surface as failures with the original message."""
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.side_effect = ConnectionError(
                "Connection refused"
            )
            service = ScrapeService()
            result = service.scrape(
                ScrapeOptions(url="https://example.com/down", check_robots=False)
            )
            service.close()

        assert result.success is False
        assert "Connection refused" in (result.error or "")
        assert result.error_code == "EXECUTION_ERROR"

    def test_static_robots_block_propagates_reason(self):
        """robots.txt blocking keeps its reason in the service error."""
        with (
            patch("ciberwebscan.core.client.HTTPClient"),
            patch(
                "ciberwebscan.core.scraping.static.check_robots_txt",
                return_value=(False, "Blocked by robots.txt"),
            ),
        ):
            service = ScrapeService()
            result = service.scrape(
                ScrapeOptions(url="https://example.com/private", check_robots=True)
            )
            service.close()

        assert result.success is False
        assert "robots" in (result.error or "").lower()
        assert result.error_code == "EXECUTION_ERROR"

    def test_ssrf_blocked_url_keeps_validation_error(self):
        """SSRF protection still classifies as VALIDATION_ERROR."""
        service = ScrapeService()
        result = service.scrape(
            ScrapeOptions(url="http://169.254.169.254/latest/meta-data/")
        )
        service.close()

        assert result.success is False
        assert result.error_code == "VALIDATION_ERROR"
        assert "ssrf" in (result.error or "").lower()

    def test_static_failure_is_not_exported(self):
        """Failed scrapes never produce export artifacts."""
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(500)
            service = ScrapeService()
            result = service.scrape(
                ScrapeOptions(
                    url="https://example.com/error",
                    check_robots=False,
                    export="out.json",
                )
            )
            service.close()

        assert result.success is False
        assert not result.exported
        assert result.export_path is None

    def test_dynamic_failure_does_not_fabricate_http_200(self):
        """Dynamic engine failures propagate without fake success metadata."""
        failed = DynamicScrapeResult(
            url="https://example.com/spa",
            success=False,
            error="Timeout waiting for page",
        )
        with (
            patch(
                "ciberwebscan.services.scrape_service.is_playwright_available",
                return_value=True,
            ),
            patch(
                "ciberwebscan.services.scrape_service.run_async",
                return_value=failed,
            ),
        ):
            service = ScrapeService()
            service._dynamic_scraper = Mock()
            service._dynamic_scraper.scrape = Mock(return_value=failed)
            result = service.scrape(
                ScrapeOptions(url="https://example.com/spa", dynamic=True)
            )
            service.close()

        assert result.success is False
        assert "Timeout waiting for page" in (result.error or "")
        assert result.error_code == "EXECUTION_ERROR"
        assert result.data is None

    def test_dynamic_success_still_maps_result(self):
        """Dynamic engine successes keep mapping to a valid ScrapeResult."""
        ok = DynamicScrapeResult(
            url="https://example.com/spa",
            success=True,
            html="<html><head><title>Spa</title></head><body>ready</body></html>",
            title="Spa",
        )
        with (
            patch(
                "ciberwebscan.services.scrape_service.is_playwright_available",
                return_value=True,
            ),
            patch(
                "ciberwebscan.services.scrape_service.run_async",
                return_value=ok,
            ),
        ):
            service = ScrapeService()
            service._dynamic_scraper = Mock()
            service._dynamic_scraper.scrape = Mock(return_value=ok)
            result = service.scrape(
                ScrapeOptions(url="https://example.com/spa", dynamic=True)
            )
            service.close()

        assert result.success is True
        assert isinstance(result.data, ScrapeResult)
        assert result.data.title == "Spa"
        assert result.data.status_code == 200

    def test_batch_mixed_counts_and_warns_failures(self):
        """Mixed batches keep successes, count failures, warn with reason."""
        ok_response = _mock_http_response(200)
        missing_response = _mock_http_response(404, "<html>Not Found</html>")
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.side_effect = lambda url, **kwargs: (
                ok_response if url.endswith("/ok") else missing_response
            )
            service = ScrapeService()
            result = service.scrape_multiple(
                [
                    "https://example.com/ok",
                    "https://example.com/missing",
                ],
                ScrapeOptions(url="https://example.com", check_robots=False),
            )
            service.close()

        assert result.success is True
        assert len(result.data) == 1
        assert result.data[0].url == "https://example.com/ok"
        assert len(result.warnings) == 1
        assert "404" in result.warnings[0]

    def test_batch_all_failures_is_informative_failure(self):
        """A fully failed batch is a failure with an informative error."""
        with patch("ciberwebscan.core.client.HTTPClient") as mock_http_cls:
            mock_http_cls.return_value.get.return_value = _mock_http_response(
                404, "<html>Not Found</html>"
            )
            service = ScrapeService()
            result = service.scrape_multiple(
                [
                    "https://example.com/a",
                    "https://example.com/b",
                ],
                ScrapeOptions(url="https://example.com", check_robots=False),
            )
            service.close()

        assert result.success is False
        assert result.data == []
        assert result.error_code == "SCRAPE_ERROR"
        assert "404" in (result.error or "")
        assert len(result.warnings) == 2
