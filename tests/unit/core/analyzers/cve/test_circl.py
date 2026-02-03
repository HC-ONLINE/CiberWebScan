"""
Unit tests for CIRCL CVE client.

Tests the CIRCL API client with mocked HTTP responses.
"""

from unittest.mock import Mock, patch

from ciberwebscan.core.analyzers.cve.circl import CIRCLClient, lookup_cves_circl
from ciberwebscan.core.analyzers.cve.models import (
    CVESearchQuery,
    CVESource,
)


class TestCIRCLClient:
    """Tests for CIRCLClient class."""

    def test_init_default_config(self) -> None:
        """Test client initialization with default config."""
        with patch("ciberwebscan.core.analyzers.cve.circl.HTTPClient"):
            client = CIRCLClient()
            assert "cve.circl.lu" in client.api_url
            assert client.timeout == 30

    def test_init_custom_config(self) -> None:
        """Test client initialization with custom config."""
        with patch("ciberwebscan.core.analyzers.cve.circl.HTTPClient"):
            client = CIRCLClient(timeout=60, throttle=2.0)
            assert client.timeout == 60
            assert client.throttle == 2.0

    def test_search_requires_vendor_and_product(self) -> None:
        """Test that search requires both vendor and product."""
        with patch("ciberwebscan.core.analyzers.cve.circl.HTTPClient"):
            client = CIRCLClient()

            # Missing both
            query = CVESearchQuery()
            result = client.search(query)
            assert result.has_error is True
            assert "requires" in result.error.lower()

            # Missing product
            query = CVESearchQuery(vendor="Apache")
            result = client.search(query)
            assert result.has_error is True

    def test_search_basic(self) -> None:
        """Test basic search functionality."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "CVE-2021-44228",
                "summary": "Apache Log4j2 RCE vulnerability",
                "cvss": 10.0,
            }
        ]

        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = CIRCLClient()
            query = CVESearchQuery(vendor="Apache", product="Log4j")
            result = client.search(query)

            assert result.source == CVESource.CIRCL
            assert len(result.entries) == 1
            assert result.entries[0].id == "CVE-2021-44228"

    def test_search_error_handling(self) -> None:
        """Test error handling on API failure."""
        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.side_effect = Exception("Connection failed")
            mock_http_client.return_value = mock_client

            client = CIRCLClient()
            query = CVESearchQuery(vendor="test", product="test")
            result = client.search(query)

            assert result.has_error is True
            assert "Connection failed" in result.error

    def test_search_empty_response(self) -> None:
        """Test handling of empty response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []

        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = CIRCLClient()
            query = CVESearchQuery(vendor="test", product="test")
            result = client.search(query)

            assert result.has_error is False
            assert len(result.entries) == 0

    def test_search_by_cve_id(self) -> None:
        """Test fetching a specific CVE by ID."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "CVE-2021-44228",
            "summary": "Log4j RCE",
            "cvss": {"score": 10.0, "version": "3.1"},
            "references": ["https://example.com/ref1"],
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = CIRCLClient()
            entry = client.search_by_cve_id("CVE-2021-44228")

            assert entry is not None
            assert entry.id == "CVE-2021-44228"
            assert entry.source == CVESource.CIRCL


class TestLookupCVEsCIRCL:
    """Tests for the convenience function."""

    def test_lookup_cves_circl_basic(self) -> None:
        """Test basic usage of convenience function."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []

        with patch(
            "ciberwebscan.core.analyzers.cve.circl.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            result = lookup_cves_circl("Apache", "Log4j")
            assert isinstance(result, list)
