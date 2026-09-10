"""Lifecycle regression tests for HTTPClient resource leak fixes.

Tests cover:
- CVE clients (NVDClient, CIRCLClient, VulnersClient)
- CVEAggregator
- StaticScraper
- ScrapeService ad-hoc scrapers
- scrape_static() convenience function
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ciberwebscan.core.client.http_client import HTTPClient

# === CVE Client Lifecycle Tests ===


class TestNVDClientLifecycle:
    """Test NVDClient HTTPClient lifecycle."""

    def test_close_releases_resources(self):
        """NVDClient.close() should close the underlying HTTPClient."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.nvd import NVDClient

            client = NVDClient()
            client.close()
            mock_http.close.assert_called_once()

    def test_context_manager_closes(self):
        """NVDClient context manager should close HTTPClient on exit."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.nvd import NVDClient

            with NVDClient():
                pass
            mock_http.close.assert_called_once()

    def test_context_manager_closes_on_exception(self):
        """NVDClient context manager should close even on exception."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.nvd import NVDClient

            with pytest.raises(RuntimeError), NVDClient():
                raise RuntimeError("test")
            mock_http.close.assert_called_once()


class TestCIRCLClientLifecycle:
    """Test CIRCLClient HTTPClient lifecycle."""

    def test_close_releases_resources(self):
        """CIRCLClient.close() should close the underlying HTTPClient."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.circl import CIRCLClient

            client = CIRCLClient()
            client.close()
            mock_http.close.assert_called_once()

    def test_context_manager_closes(self):
        """CIRCLClient context manager should close HTTPClient on exit."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.circl import CIRCLClient

            with CIRCLClient():
                pass
            mock_http.close.assert_called_once()

    def test_context_manager_closes_on_exception(self):
        """CIRCLClient context manager should close even on exception."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.circl import CIRCLClient

            with pytest.raises(RuntimeError), CIRCLClient():
                raise RuntimeError("test")
            mock_http.close.assert_called_once()


class TestVulnersClientLifecycle:
    """Test VulnersClient HTTPClient lifecycle."""

    def test_close_releases_resources(self):
        """VulnersClient.close() should close the underlying HTTPClient."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.vulners.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.vulners import VulnersClient

            client = VulnersClient()
            client.close()
            mock_http.close.assert_called_once()

    def test_context_manager_closes(self):
        """VulnersClient context manager should close HTTPClient on exit."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.vulners.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.vulners import VulnersClient

            with VulnersClient():
                pass
            mock_http.close.assert_called_once()

    def test_context_manager_closes_on_exception(self):
        """VulnersClient context manager should close even on exception."""
        mock_http = MagicMock()
        with patch(
            "ciberwebscan.core.analyzers.cve.vulners.HTTPClient", return_value=mock_http
        ):
            from ciberwebscan.core.analyzers.cve.vulners import VulnersClient

            with pytest.raises(RuntimeError), VulnersClient():
                raise RuntimeError("test")
            mock_http.close.assert_called_once()


# === CVEAggregator Lifecycle Tests ===


class TestCVEAggregatorLifecycle:
    """Test CVEAggregator close propagation."""

    def test_close_propagates_to_all_clients(self):
        """CVEAggregator.close() should close all sub-clients."""
        mock_nvd = MagicMock()
        mock_circl = MagicMock()
        mock_vulners = MagicMock()

        with (
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.NVDClient",
                return_value=mock_nvd,
            ),
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.CIRCLClient",
                return_value=mock_circl,
            ),
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.VulnersClient",
                return_value=mock_vulners,
            ),
        ):
            from ciberwebscan.core.analyzers.cve.aggregator import CVEAggregator

            agg = CVEAggregator()
            agg.close()
            mock_nvd.close.assert_called_once()
            mock_circl.close.assert_called_once()
            mock_vulners.close.assert_called_once()

    def test_context_manager_closes_all(self):
        """CVEAggregator context manager should close all clients on exit."""
        mock_nvd = MagicMock()
        mock_circl = MagicMock()
        mock_vulners = MagicMock()

        with (
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.NVDClient",
                return_value=mock_nvd,
            ),
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.CIRCLClient",
                return_value=mock_circl,
            ),
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.VulnersClient",
                return_value=mock_vulners,
            ),
        ):
            from ciberwebscan.core.analyzers.cve.aggregator import CVEAggregator

            with CVEAggregator():
                pass
            mock_nvd.close.assert_called_once()
            mock_circl.close.assert_called_once()
            mock_vulners.close.assert_called_once()

    def test_context_manager_closes_on_exception(self):
        """CVEAggregator context manager should close even on exception."""
        mock_nvd = MagicMock()
        mock_circl = MagicMock()
        mock_vulners = MagicMock()

        with (
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.NVDClient",
                return_value=mock_nvd,
            ),
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.CIRCLClient",
                return_value=mock_circl,
            ),
            patch(
                "ciberwebscan.core.analyzers.cve.aggregator.VulnersClient",
                return_value=mock_vulners,
            ),
        ):
            from ciberwebscan.core.analyzers.cve.aggregator import CVEAggregator

            with pytest.raises(RuntimeError), CVEAggregator():
                raise RuntimeError("test")
            mock_nvd.close.assert_called_once()
            mock_circl.close.assert_called_once()
            mock_vulners.close.assert_called_once()


# === StaticScraper Lifecycle Tests ===


class TestStaticScraperLifecycle:
    """Test StaticScraper close and proxy client management."""

    def test_close_closes_proxy_client(self):
        """StaticScraper.close() should close the proxy client."""
        from ciberwebscan.core.scraping.static import StaticScraper

        mock_client = MagicMock()
        mock_proxy_client = MagicMock()

        scraper = StaticScraper(mock_client)
        scraper._proxy_client = mock_proxy_client
        scraper._last_proxy = "http://proxy:8080"

        scraper.close()

        mock_proxy_client.close.assert_called_once()
        assert scraper._proxy_client is None
        assert scraper._last_proxy is None

    def test_context_manager_closes(self):
        """StaticScraper context manager should close proxy client on exit."""
        from ciberwebscan.core.scraping.static import StaticScraper

        mock_client = MagicMock()
        mock_proxy_client = MagicMock()

        with StaticScraper(mock_client) as scraper:
            scraper._proxy_client = mock_proxy_client
            scraper._last_proxy = "http://proxy:8080"

        mock_proxy_client.close.assert_called_once()

    def test_proxy_change_closes_old_client(self):
        """Changing proxy should close the old proxy client."""
        from ciberwebscan.core.scraping.static import StaticScraper

        mock_client = MagicMock()
        scraper = StaticScraper(mock_client)

        # Simulate first proxy
        old_proxy_client = MagicMock()
        scraper._proxy_client = old_proxy_client
        scraper._last_proxy = "http://proxy1:8080"

        # Simulate proxy change via _get_client
        mock_rotator = MagicMock()
        mock_rotator.next.return_value = "http://proxy2:8080"
        scraper._proxy_rotator = mock_rotator

        new_client = scraper._get_client()

        old_proxy_client.close.assert_called_once()
        assert scraper._last_proxy == "http://proxy2:8080"
        assert new_client is not scraper._client

    def test_same_proxy_reuses_client(self):
        """Same proxy should reuse cached client, not create new one."""
        from ciberwebscan.core.scraping.static import StaticScraper

        mock_client = MagicMock()
        scraper = StaticScraper(mock_client)

        mock_rotator = MagicMock()
        mock_rotator.next.return_value = "http://proxy1:8080"
        scraper._proxy_rotator = mock_rotator

        client1 = scraper._get_client()
        client2 = scraper._get_client()

        assert client1 is client2


# === ScrapeService Ad-hoc Scraper Tests ===


class TestScrapeServiceAdHocScrapers:
    """Test ScrapeService tracking and cleanup of ad-hoc scrapers."""

    def test_ad_hoc_scrapers_tracked(self):
        """Ad-hoc scrapers should be tracked in _ad_hoc_scrapers list."""
        from ciberwebscan.services.scrape_service import ScrapeService

        service = ScrapeService.__new__(ScrapeService)
        service._ad_hoc_scrapers = []
        service._proxy_rotator = None
        service._user_agent_provider = MagicMock()
        service.app_config = MagicMock()

        mock_client = MagicMock()
        with patch.object(service, "_build_http_client", return_value=mock_client):
            scraper = service._get_static_scraper_with_proxy(
                proxy="http://proxy:8080",
                verify_ssl=True,
                cookies=None,
            )

        assert len(service._ad_hoc_scrapers) == 1
        assert service._ad_hoc_scrapers[0] is scraper

    def test_close_cleans_ad_hoc_scrapers(self):
        """ScrapeService.close() should close all ad-hoc scrapers."""
        from ciberwebscan.services.scrape_service import ScrapeService

        service = ScrapeService.__new__(ScrapeService)
        mock_scraper1 = MagicMock()
        mock_scraper2 = MagicMock()
        service._ad_hoc_scrapers = [mock_scraper1, mock_scraper2]
        service._static_scraper = None
        service._dynamic_scraper = None

        service.close()

        mock_scraper1.close.assert_called_once()
        mock_scraper2.close.assert_called_once()
        assert len(service._ad_hoc_scrapers) == 0

    def test_default_scraper_not_tracked_as_ad_hoc(self):
        """Default scraper (no proxy/cookies) should not be tracked as ad-hoc."""
        from ciberwebscan.services.scrape_service import ScrapeService

        service = ScrapeService.__new__(ScrapeService)
        service._ad_hoc_scrapers = []
        service._proxy_rotator = None
        service._user_agent_provider = MagicMock()
        service.app_config = MagicMock()
        service._static_scraper = MagicMock()

        scraper = service._get_static_scraper_with_proxy(
            proxy=None,
            verify_ssl=True,
            cookies=None,
        )

        assert len(service._ad_hoc_scrapers) == 0
        assert scraper is service._static_scraper


# === scrape_static() Convenience Function Tests ===


class TestScrapeStaticConvenience:
    """Test scrape_static() convenience function cleanup."""

    def test_creates_and_closes_client(self):
        """scrape_static() should create and close its own HTTPClient."""
        from ciberwebscan.core.scraping.static import scrape_static

        with patch(
            "ciberwebscan.core.scraping.static.StaticScraper"
        ) as mock_scraper_cls:
            mock_scraper = MagicMock()
            mock_scraper_cls.return_value = mock_scraper
            mock_scraper.scrape_pages.return_value = MagicMock()

            scrape_static("http://example.com", "body")

            # Verify HTTPClient was created and passed to StaticScraper
            mock_scraper_cls.assert_called_once()
            call_args = mock_scraper_cls.call_args
            client_arg = call_args[0][0]

            # Verify client is an HTTPClient instance
            assert isinstance(client_arg, HTTPClient)

    def test_does_not_close_provided_client(self):
        """scrape_static() should NOT close a client provided by the caller."""
        from ciberwebscan.core.scraping.static import scrape_static

        mock_client = MagicMock()

        with patch(
            "ciberwebscan.core.scraping.static.StaticScraper"
        ) as mock_scraper_cls:
            mock_scraper = MagicMock()
            mock_scraper_cls.return_value = mock_scraper
            mock_scraper.scrape_pages.return_value = MagicMock()

            scrape_static("http://example.com", "body", http_client=mock_client)

            # Provided client should NOT be closed
            mock_client.close.assert_not_called()

    def test_closes_client_on_exception(self):
        """scrape_static() should close client even on exception."""
        from ciberwebscan.core.scraping.static import scrape_static

        with patch(
            "ciberwebscan.core.scraping.static.StaticScraper"
        ) as mock_scraper_cls:
            mock_scraper = MagicMock()
            mock_scraper_cls.return_value = mock_scraper
            mock_scraper.scrape_pages.side_effect = RuntimeError("test")

            with pytest.raises(RuntimeError):
                scrape_static("http://example.com", "body")


# === AnalyzeService Lifecycle Tests ===


class TestAnalyzeServiceLifecycle:
    """Test AnalyzeService close propagation to CVEAggregator."""

    def test_close_closes_cve_aggregator(self):
        """AnalyzeService.close() should close the CVE aggregator."""
        with patch("ciberwebscan.services.analyze_service.get_config"):
            from ciberwebscan.services.analyze_service import AnalyzeService

            service = AnalyzeService.__new__(AnalyzeService)
            mock_aggregator = MagicMock()
            service._cve_aggregator = mock_aggregator

            service.close()

            mock_aggregator.close.assert_called_once()
            assert service._cve_aggregator is None

    def test_context_manager_closes_aggregator(self):
        """AnalyzeService context manager should close aggregator on exit."""
        with patch("ciberwebscan.services.analyze_service.get_config"):
            from ciberwebscan.services.analyze_service import AnalyzeService

            service = AnalyzeService.__new__(AnalyzeService)
            mock_aggregator = MagicMock()
            service._cve_aggregator = mock_aggregator

            with service:
                pass

            mock_aggregator.close.assert_called_once()
