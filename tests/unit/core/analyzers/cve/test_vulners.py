"""
Unit tests for Vulners CVE client.

Tests the Vulners API client with mocked HTTP responses.
"""

from unittest.mock import Mock, patch

from ciberwebscan.core.analyzers.cve.models import CVESource
from ciberwebscan.core.analyzers.cve.vulners import VulnersClient, get_exploit_info


class TestVulnersClient:
    """Tests for VulnersClient class."""

    def test_init_default_config(self) -> None:
        """Test client initialization with default config."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("ciberwebscan.core.analyzers.cve.vulners.HTTPClient"),
        ):
            client = VulnersClient()
            assert client.timeout == 30
            assert client.enabled is False  # No API key

    def test_init_with_api_key(self) -> None:
        """Test client initialization with API key."""
        with patch("ciberwebscan.core.analyzers.cve.vulners.HTTPClient"):
            client = VulnersClient(api_key="test-api-key")
            assert client.api_key == "test-api-key"
            assert client.enabled is True

    def test_init_with_env_api_key(self) -> None:
        """Test client uses env var for API key."""
        with (
            patch.dict("os.environ", {"VULNERS_API_KEY": "env-api-key"}),
            patch("ciberwebscan.core.analyzers.cve.vulners.HTTPClient"),
        ):
            client = VulnersClient()
            assert client.api_key == "env-api-key"
            assert client.enabled is True

    def test_search_by_software(self) -> None:
        """Test searching by software name and version."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2021-44228",
                            "title": "Log4j RCE",
                            "description": "RCE vulnerability",
                            "cvss": {"score": 10.0},
                            "type": "cve",
                        }
                    },
                ]
            },
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.vulners.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.post.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = VulnersClient(api_key="test-key")
            result = client.search_by_software("log4j", "2.14.1")

            assert result.source == CVESource.VULNERS

    def test_search_error_handling(self) -> None:
        """Test error handling on API failure."""
        with patch(
            "ciberwebscan.core.analyzers.cve.vulners.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.post.side_effect = Exception("Connection timeout")
            mock_http_client.return_value = mock_client

            client = VulnersClient(api_key="test-key")
            result = client.search_by_software("test", "1.0")

            assert result.has_error is True
            assert "Connection timeout" in result.error

    def test_disabled_without_api_key(self) -> None:
        """Test that client is disabled without API key."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("ciberwebscan.core.analyzers.cve.vulners.HTTPClient"),
        ):
            client = VulnersClient()
            assert client.enabled is False

    def test_get_exploits(self) -> None:
        """Test fetching exploits for a CVE."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": "OK",
            "data": {
                "documents": {
                    "EDB-123": {
                        "type": "exploit",
                        "title": "Test Exploit",
                        "href": "https://example.com/exploit",
                    }
                }
            },
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.vulners.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.post.return_value = mock_response
            mock_http_client.return_value = mock_client

            client = VulnersClient(api_key="test-key")
            exploits = client.get_exploits("CVE-2021-44228")

            assert len(exploits) == 1
            assert exploits[0]["id"] == "EDB-123"


class TestGetExploitInfo:
    """Tests for the convenience function."""

    def test_get_exploit_info_convenience(self) -> None:
        """Test basic usage of convenience function."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": "OK",
            "data": {
                "documents": {
                    "EDB-123": {
                        "type": "exploit",
                        "title": "Exploit",
                    }
                },
            },
        }

        with patch(
            "ciberwebscan.core.analyzers.cve.vulners.HTTPClient"
        ) as mock_http_client:
            mock_client = Mock()
            mock_client.post.return_value = mock_response
            mock_http_client.return_value = mock_client

            info = get_exploit_info("CVE-2021-44228", api_key="test-key")

            assert info["cve_id"] == "CVE-2021-44228"

    def test_get_exploit_info_no_api_key(self) -> None:
        """Test convenience function without API key."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("ciberwebscan.core.analyzers.cve.vulners.HTTPClient"),
        ):
            info = get_exploit_info("CVE-2021-44228")

            assert info["cve_id"] == "CVE-2021-44228"
            assert info["has_exploits"] is False
            assert "error" in info
