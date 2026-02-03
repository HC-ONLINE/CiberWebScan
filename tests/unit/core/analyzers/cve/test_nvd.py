"""
Unit tests for NVD CVE client.

Tests the NVD API client with mocked HTTP responses.
"""

from unittest.mock import Mock, patch

from ciberwebscan.core.analyzers.cve.models import (
    CVESearchQuery,
    CVESource,
)
from ciberwebscan.core.analyzers.cve.nvd import (
    PRODUCT_TO_CPE,
    NVDClient,
    lookup_cves_nvd,
)


class TestNVDClient:
    """Tests for NVDClient class."""

    def test_init_default_config(self) -> None:
        """Test client initialization with default config."""
        with patch("ciberwebscan.core.analyzers.cve.nvd.HTTPClient"):
            client = NVDClient()
            assert "nvd.nist.gov" in client.api_url
            assert client.timeout == 45

    def test_init_with_api_key(self) -> None:
        """Test client initialization with API key."""
        with patch("ciberwebscan.core.analyzers.cve.nvd.HTTPClient"):
            client = NVDClient(api_key="test-key-12345")
            assert client.api_key == "test-key-12345"

    def test_search_by_keyword(self) -> None:
        """Test search by keyword."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [
                            {"lang": "en", "value": "Apache Log4j2 RCE vulnerability"}
                        ],
                        "published": "2021-12-10T10:15:08.000",
                        "lastModified": "2021-12-15T14:30:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 10.0,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    },
                                    "impactScore": 6.0,
                                    "exploitabilityScore": 3.9,
                                }
                            ]
                        },
                        "references": [
                            {
                                "url": "https://logging.apache.org/log4j/2.x/security.html",
                                "source": "Apache",
                                "tags": ["Vendor Advisory"],
                            }
                        ],
                        "weaknesses": [
                            {"description": [{"lang": "en", "value": "CWE-502"}]}
                        ],
                    }
                }
            ],
            "totalResults": 1,
            "resultsPerPage": 20,
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = NVDClient()
            query = CVESearchQuery(vendor="apache", product="log4j", limit=20)
            result = client.search(query)

            assert result.source == CVESource.NVD
            assert len(result.entries) == 1
            entry = result.entries[0]
            assert entry.id == "CVE-2021-44228"

    def test_search_empty_result(self) -> None:
        """Test search with no results."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [],
            "totalResults": 0,
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = NVDClient()
            query = CVESearchQuery(vendor="test", product="test")
            result = client.search(query)

            assert result.has_error is False
            assert len(result.entries) == 0

    def test_search_error_handling(self) -> None:
        """Test error handling on API failure."""
        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.side_effect = Exception("Network error")
            mock_http_client.return_value = mock_client

            client = NVDClient()
            query = CVESearchQuery(vendor="test", product="test")
            result = client.search(query)

            assert result.has_error is True
            assert "Network error" in result.error

    def test_get_cve(self) -> None:
        """Test fetching a specific CVE."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Log4j RCE"}],
                        "metrics": {},
                    }
                }
            ],
            "totalResults": 1,
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = NVDClient()
            entry = client.get_cve("CVE-2021-44228")

            assert entry is not None
            assert entry.id == "CVE-2021-44228"

    def test_clear_cache(self) -> None:
        """Test cache clearing."""
        with patch("ciberwebscan.core.analyzers.cve.nvd.HTTPClient"):
            client = NVDClient()
            # The cache method exists
            assert hasattr(client, "clear_cache")


class TestProductToCPE:
    """Tests for CPE mapping."""

    def test_common_products_mapped(self) -> None:
        """Test that common products have CPE mappings."""
        assert "wordpress" in PRODUCT_TO_CPE
        assert "nginx" in PRODUCT_TO_CPE
        assert "apache" in PRODUCT_TO_CPE
        assert "jquery" in PRODUCT_TO_CPE

    def test_cpe_format(self) -> None:
        """Test CPE format is valid."""
        for product, cpe in PRODUCT_TO_CPE.items():
            assert cpe.startswith("cpe:2.3:a:"), f"Invalid CPE for {product}: {cpe}"


class TestLookupCVEsNVD:
    """Tests for the convenience function."""

    def test_lookup_cves_nvd_basic(self) -> None:
        """Test basic usage of convenience function."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [],
            "totalResults": 0,
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.nvd.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.get.return_value = mock_response
            mock_http_client.return_value = mock_client

            result = lookup_cves_nvd("wordpress")
            assert result.source == CVESource.NVD
