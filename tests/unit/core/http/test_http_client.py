"""
Unit tests for HTTPClient and RateLimiter.
"""

import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from ciberwebscan.core.http import HTTPClient, RateLimiter


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_init_default(self):
        """Test RateLimiter with default rate."""
        limiter = RateLimiter()
        assert limiter._min_interval == 0.2  # 5 req/s = 0.2s interval

    def test_init_custom_rate(self):
        """Test RateLimiter with custom rate."""
        limiter = RateLimiter(requests_per_second=10.0)
        assert limiter._min_interval == 0.1  # 10 req/s = 0.1s interval

    def test_first_request_no_wait(self):
        """First request to a domain should not wait."""
        limiter = RateLimiter(requests_per_second=2.0)
        waited = limiter.wait("example.com")
        assert waited == 0.0

    def test_subsequent_request_waits(self):
        """Subsequent requests should wait to respect rate limit."""
        limiter = RateLimiter(requests_per_second=10.0)  # 0.1s interval

        # First request - no wait
        limiter.wait("example.com")

        # Immediate second request - should wait
        start = time.monotonic()
        limiter.wait("example.com")
        elapsed = time.monotonic() - start

        # Should have waited approximately 0.1s
        assert elapsed >= 0.08  # Allow some tolerance

    def test_different_domains_independent(self):
        """Different domains should have independent rate limits."""
        limiter = RateLimiter(requests_per_second=2.0)

        # First domain
        limiter.wait("domain1.com")
        # Second domain - should not wait
        waited = limiter.wait("domain2.com")
        assert waited == 0.0

    def test_clear_specific_domain(self):
        """Clearing a specific domain should reset only that domain."""
        limiter = RateLimiter(requests_per_second=2.0)

        limiter.wait("domain1.com")
        limiter.wait("domain2.com")

        limiter.clear("domain1.com")

        # domain1 should be cleared
        assert "domain1.com" not in limiter._last_request
        # domain2 should still exist
        assert "domain2.com" in limiter._last_request

    def test_clear_all_domains(self):
        """Clearing without domain should reset all."""
        limiter = RateLimiter()

        limiter.wait("domain1.com")
        limiter.wait("domain2.com")

        limiter.clear()

        assert len(limiter._last_request) == 0


class TestHTTPClient:
    """Tests for HTTPClient class."""

    def test_init_defaults(self):
        """Test HTTPClient with default parameters."""
        client = HTTPClient()
        # Check via internal client, not direct attributes
        assert client._max_retries == 3
        assert client._backoff_factor == 0.5
        assert client._proxy is None
        assert client._rate_limiter is None
        client.close()

    def test_init_with_rate_limit(self):
        """Test HTTPClient with rate limiting enabled."""
        client = HTTPClient(rate_limit=5.0)
        assert client._rate_limiter is not None
        client.close()

    def test_init_with_proxy(self):
        """Test HTTPClient with proxy configured."""
        client = HTTPClient(proxy="http://proxy.com:8080")
        assert client._proxy == "http://proxy.com:8080"
        client.close()

    def test_context_manager(self):
        """Test HTTPClient as context manager."""
        with HTTPClient() as client:
            assert isinstance(client, HTTPClient)
        # Client should be closed after exiting context

    def test_retryable_status_codes(self):
        """Test that retryable status codes are defined correctly."""
        assert 429 in HTTPClient.RETRYABLE_STATUS_CODES
        assert 500 in HTTPClient.RETRYABLE_STATUS_CODES
        assert 502 in HTTPClient.RETRYABLE_STATUS_CODES
        assert 503 in HTTPClient.RETRYABLE_STATUS_CODES
        assert 504 in HTTPClient.RETRYABLE_STATUS_CODES
        assert 200 not in HTTPClient.RETRYABLE_STATUS_CODES
        assert 404 not in HTTPClient.RETRYABLE_STATUS_CODES

    @patch.object(httpx.Client, "request")
    def test_get_request(self, mock_request):
        """Test GET request method."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        with HTTPClient() as client:
            response = client.get("https://example.com")

        assert response.status_code == 200
        mock_request.assert_called_once()

    @patch.object(httpx.Client, "request")
    def test_post_request(self, mock_request):
        """Test POST request method."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 201
        mock_request.return_value = mock_response

        with HTTPClient() as client:
            response = client.post("https://example.com/api", json={"key": "value"})

        assert response.status_code == 201

    @patch.object(httpx.Client, "request")
    def test_metrics_callback(self, mock_request):
        """Test that metrics callback is called."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        metrics_calls = []

        def my_metrics(method, url, status, duration):
            metrics_calls.append((method, url, status))

        with HTTPClient(metrics_callback=my_metrics) as client:
            client.get("https://example.com")

        assert len(metrics_calls) == 1
        assert metrics_calls[0] == ("GET", "https://example.com", 200)

    @patch.object(httpx.Client, "request")
    def test_retry_on_timeout(self, mock_request):
        """Test retry on timeout exception."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200

        # First call raises timeout, second succeeds
        mock_request.side_effect = [
            httpx.TimeoutException("Timeout"),
            mock_response,
        ]

        with HTTPClient(max_retries=2, backoff_factor=0.01) as client:
            response = client.get("https://example.com")

        assert response.status_code == 200
        assert mock_request.call_count == 2

    @patch.object(httpx.Client, "request")
    def test_no_retry_when_disabled(self, mock_request):
        """Test that retry can be disabled per request."""
        mock_request.side_effect = httpx.TimeoutException("Timeout")

        with HTTPClient(max_retries=3) as client, pytest.raises(httpx.TimeoutException):
            client.get("https://example.com", retry=False)

        # Should only try once when retry=False
        assert mock_request.call_count == 1

    @patch.object(httpx.Client, "request")
    def test_retry_on_retryable_status(self, mock_request):
        """Test retry on retryable status codes."""
        mock_response_503 = MagicMock(spec=httpx.Response)
        mock_response_503.status_code = 503
        mock_response_503.headers = {}

        mock_response_200 = MagicMock(spec=httpx.Response)
        mock_response_200.status_code = 200

        mock_request.side_effect = [mock_response_503, mock_response_200]

        with HTTPClient(max_retries=2, backoff_factor=0.01) as client:
            response = client.get("https://example.com")

        assert response.status_code == 200
        assert mock_request.call_count == 2

    def test_convenience_methods_exist(self):
        """Test that all convenience methods exist."""
        client = HTTPClient()
        assert hasattr(client, "get")
        assert hasattr(client, "post")
        assert hasattr(client, "put")
        assert hasattr(client, "patch")
        assert hasattr(client, "delete")
        assert hasattr(client, "head")
        assert hasattr(client, "options")
        client.close()


class TestHTTPClientIntegration:
    """Integration tests for HTTPClient (require network)."""

    @pytest.mark.integration
    def test_real_get_request(self):
        """Test real GET request to httpbin."""
        with HTTPClient(timeout=10.0) as client:
            response = client.get("https://httpbin.org/get")
        assert response.status_code == 200
        assert "headers" in response.json()

    @pytest.mark.integration
    def test_real_post_request(self):
        """Test real POST request to httpbin."""
        with HTTPClient(timeout=10.0) as client:
            response = client.post(
                "https://httpbin.org/post",
                json={"test": "data"},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["json"] == {"test": "data"}
