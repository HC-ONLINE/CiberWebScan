"""
Unit tests for HTTPClient and RateLimiter.
"""

import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from ciberwebscan.core.client import HTTPClient, RateLimiter


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_init_default(self):
        """Test RateLimiter with default rate."""
        limiter = RateLimiter()
        assert limiter._initial_rate == 5.0  # default 5 req/s

    def test_init_custom_rate(self):
        """Test RateLimiter with custom rate."""
        limiter = RateLimiter(requests_per_second=10.0)
        assert limiter._initial_rate == 10.0  # custom 10 req/s

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


class TestRateLimiterAdaptive:
    """Tests for adaptive rate limiting behavior (AIMD)."""

    def test_adaptive_disabled_by_default(self):
        limiter = RateLimiter(requests_per_second=5.0)
        assert limiter._adaptive is False

    def test_adaptive_disabled_no_change_on_429(self):
        limiter = RateLimiter(requests_per_second=4.0, adaptive=False)
        for _ in range(10):
            limiter.on_response(429, 0.1, "example.com")
        assert limiter.current_rate("example.com") == 4.0

    def test_adaptive_enabled_init(self):
        limiter = RateLimiter(requests_per_second=5.0, adaptive=True)
        assert limiter.current_rate("example.com") == 5.0

    def test_on_response_429_decreases_rate(self):
        limiter = RateLimiter(
            requests_per_second=4.0,
            adaptive=True,
            decrease_factor=0.5,
        )
        limiter.on_response(429, 0.1, "example.com")
        assert limiter.current_rate("example.com") == 2.0

    def test_on_response_429_multiple_decreases(self):
        limiter = RateLimiter(
            requests_per_second=8.0,
            adaptive=True,
            decrease_factor=0.5,
        )
        limiter.on_response(429, 0.1, "example.com")
        assert limiter.current_rate("example.com") == 4.0
        limiter.on_response(429, 0.1, "example.com")
        assert limiter.current_rate("example.com") == 2.0

    def test_on_response_5xx_severe_decrease(self):
        limiter = RateLimiter(
            requests_per_second=4.0,
            adaptive=True,
            decrease_factor=0.5,
        )
        limiter.on_response(503, 0.1, "example.com")
        assert limiter.current_rate("example.com") == 1.0

    def test_on_response_2xx_increases_rate(self):
        limiter = RateLimiter(
            requests_per_second=5.0,
            adaptive=True,
            increase_factor=0.5,
            initial_rate=2.0,
        )
        for _ in range(5):
            limiter.on_response(200, 0.1, "example.com")
        assert limiter.current_rate("example.com") == 4.5

    def test_on_response_2xx_spike_no_increase(self):
        limiter = RateLimiter(
            requests_per_second=2.0,
            adaptive=True,
            increase_factor=0.5,
            latency_spike_factor=1.5,
        )
        for _ in range(5):
            limiter.on_response(200, 0.1, "example.com")
        rate_before = limiter.current_rate("example.com")
        limiter.on_response(200, 1.0, "example.com")
        assert limiter.current_rate("example.com") == rate_before

    def test_on_response_2xx_recovers_after_spike(self):
        limiter = RateLimiter(
            requests_per_second=10.0,
            adaptive=True,
            increase_factor=0.5,
            latency_spike_factor=1.5,
            initial_rate=2.0,
        )
        for _ in range(5):
            limiter.on_response(200, 0.1, "example.com")
        limiter.on_response(200, 1.0, "example.com")
        rate_after_spike = limiter.current_rate("example.com")
        for _ in range(5):
            limiter.on_response(200, 0.1, "example.com")
        assert limiter.current_rate("example.com") > rate_after_spike

    def test_rate_never_below_min(self):
        limiter = RateLimiter(
            requests_per_second=4.0,
            adaptive=True,
            min_rate=0.5,
            decrease_factor=0.5,
        )
        for _ in range(10):
            limiter.on_response(429, 0.1, "example.com")
        assert limiter.current_rate("example.com") >= 0.5

    def test_rate_never_above_max(self):
        limiter = RateLimiter(
            requests_per_second=2.0,
            adaptive=True,
            increase_factor=0.5,
        )
        for _ in range(100):
            limiter.on_response(200, 0.01, "example.com")
        assert limiter.current_rate("example.com") <= 2.0

    def test_thread_safety(self):
        limiter = RateLimiter(requests_per_second=10.0, adaptive=True)
        import threading

        def hit():
            for _ in range(50):
                limiter.on_response(200, 0.01, "example.com")

        threads = [threading.Thread(target=hit) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert limiter.current_rate("example.com") <= 10.0

    def test_clear_resets_latencies(self):
        limiter = RateLimiter(requests_per_second=2.0, adaptive=True)
        for _ in range(5):
            limiter.on_response(200, 0.1, "example.com")
        assert "example.com" in limiter._recent_latencies
        limiter.clear("example.com")
        assert "example.com" not in limiter._recent_latencies

    def test_clear_all_resets_latencies(self):
        limiter = RateLimiter(requests_per_second=2.0, adaptive=True)
        for _ in range(5):
            limiter.on_response(200, 0.1, "example.com")
        assert len(limiter._recent_latencies) > 0
        limiter.clear()
        assert len(limiter._recent_latencies) == 0

    def test_max_rate_property(self):
        limiter = RateLimiter(requests_per_second=7.5, adaptive=True)
        assert limiter.max_rate == 7.5

    def test_current_rate_equals_max_initially(self):
        limiter = RateLimiter(requests_per_second=3.0, adaptive=True)
        assert limiter.current_rate("any-domain.com") == 3.0

    def test_zero_requests_per_second_raises(self):
        with pytest.raises(ValueError, match="requests_per_second must be > 0"):
            RateLimiter(requests_per_second=0.0)

    def test_negative_requests_per_second_raises(self):
        with pytest.raises(ValueError, match="requests_per_second must be > 0"):
            RateLimiter(requests_per_second=-1.0)

    def test_zero_initial_rate_raises(self):
        with pytest.raises(ValueError, match="initial_rate must be > 0"):
            RateLimiter(requests_per_second=5.0, initial_rate=0.0)

    def test_per_domain_isolation(self):
        """A 429 on domain A must not affect the rate of domain B."""
        limiter = RateLimiter(
            requests_per_second=4.0,
            adaptive=True,
            decrease_factor=0.5,
        )
        limiter.on_response(429, 0.1, "bad.example.com")
        assert limiter.current_rate("bad.example.com") == 2.0
        assert limiter.current_rate("good.example.com") == 4.0


class TestHTTPClient:
    """Tests for HTTPClient class."""

    def test_init_defaults(self):
        """Test HTTPClient with default parameters."""
        client = HTTPClient()
        # Check via internal client, not direct attributes
        assert client._max_retries == 3
        assert client._backoff_factor == 0.5
        assert client._proxy is None
        assert client._rate_limiter is not None
        assert isinstance(client._rate_limiter, RateLimiter)
        assert client._rate_limiter._initial_rate == 5.0  # default from config
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

    def test_default_retryable_status_codes(self):
        """Test that default retryable status codes are defined correctly."""
        assert 429 in HTTPClient.DEFAULT_RETRYABLE_STATUS_CODES
        assert 500 in HTTPClient.DEFAULT_RETRYABLE_STATUS_CODES
        assert 502 in HTTPClient.DEFAULT_RETRYABLE_STATUS_CODES
        assert 503 in HTTPClient.DEFAULT_RETRYABLE_STATUS_CODES
        assert 504 in HTTPClient.DEFAULT_RETRYABLE_STATUS_CODES
        assert 200 not in HTTPClient.DEFAULT_RETRYABLE_STATUS_CODES
        assert 404 not in HTTPClient.DEFAULT_RETRYABLE_STATUS_CODES

    def test_retryable_status_codes_from_config(self):
        """Test that retryable status codes are loaded from config."""
        client = HTTPClient()
        # Config defaults match the class defaults
        assert 429 in client._retryable_status_codes
        assert 503 in client._retryable_status_codes
        client.close()

    def test_retryable_status_codes_override(self):
        """Test that retryable status codes can be overridden per instance."""
        custom_codes = {408, 429, 500}
        client = HTTPClient(retryable_status_codes=custom_codes)
        assert client._retryable_status_codes == {408, 429, 500}
        assert 503 not in client._retryable_status_codes
        client.close()

    @patch.object(httpx.Client, "request")
    def test_custom_retryable_codes_trigger_retry(self, mock_request):
        """Test that custom retryable codes actually trigger retries."""
        mock_response_408 = MagicMock(spec=httpx.Response)
        mock_response_408.status_code = 408
        mock_response_408.headers = {}

        mock_response_200 = MagicMock(spec=httpx.Response)
        mock_response_200.status_code = 200

        mock_request.side_effect = [mock_response_408, mock_response_200]

        with HTTPClient(
            retryable_status_codes={408, 500},
            max_retries=2,
            backoff_factor=0.01,
        ) as client:
            response = client.get("https://example.com")

        assert response.status_code == 200
        assert mock_request.call_count == 2

    @patch.object(httpx.Client, "request")
    def test_non_retryable_code_not_retried(self, mock_request):
        """Test that codes NOT in retryable set are not retried."""
        mock_response_503 = MagicMock(spec=httpx.Response)
        mock_response_503.status_code = 503

        # 503 is not in custom set, so should NOT be retried
        mock_request.return_value = mock_response_503

        with HTTPClient(
            retryable_status_codes={408},
            max_retries=3,
            backoff_factor=0.01,
        ) as client:
            response = client.get("https://example.com")

        assert response.status_code == 503
        assert mock_request.call_count == 1  # No retry

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

    def test_max_redirects_from_config(self):
        """Test that max_redirects is loaded from config (default 10)."""
        client = HTTPClient()
        assert client._client.max_redirects == 10
        client.close()

    def test_max_redirects_override(self):
        """Test that max_redirects can be overridden per instance."""
        client = HTTPClient(max_redirects=5)
        assert client._client.max_redirects == 5
        client.close()

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

    def test_negative_max_retries_raises(self):
        """Test that negative max_retries raises ValueError."""
        with pytest.raises(ValueError, match="max_retries must be >= 0"):
            HTTPClient(max_retries=-1)

    def test_negative_backoff_factor_raises(self):
        """Test that negative backoff_factor raises ValueError."""
        with pytest.raises(ValueError, match="backoff_factor must be >= 0"):
            HTTPClient(backoff_factor=-2.0)

    def test_zero_backoff_factor_allowed(self):
        """Test that backoff_factor=0 is allowed (no delay on retry)."""
        client = HTTPClient(backoff_factor=0.0, rate_limit=None)
        assert client._backoff_factor == 0.0
        client.close()

    def test_relative_url_raises(self):
        """Test that relative URL without hostname raises ValueError."""
        client = HTTPClient(rate_limit=None)
        with pytest.raises(ValueError, match="must include a hostname"):
            client.get("/api")
        client.close()

    def test_empty_url_raises(self):
        """Test that empty URL raises ValueError."""
        client = HTTPClient(rate_limit=None)
        with pytest.raises(ValueError, match="must include a hostname"):
            client.get("")
        client.close()


class TestCalculateBackoff:
    """Tests for Retry-After header parsing in _calculate_backoff."""

    def _make_response(self, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(
            status_code=429,
            headers=headers,
            request=httpx.Request("GET", "https://example.com"),
        )

    def test_retry_after_seconds(self):
        client = HTTPClient(rate_limit=None)
        resp = self._make_response({"Retry-After": "120"})
        assert client._calculate_backoff(0, resp) == 120.0
        client.close()

    def test_retry_after_http_date(self):
        from datetime import datetime, timedelta, timezone

        client = HTTPClient(rate_limit=None)
        future = datetime.now(timezone.utc) + timedelta(seconds=300)
        date_str = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp = self._make_response({"Retry-After": date_str})
        wait = client._calculate_backoff(0, resp)
        assert 290 <= wait <= 310  # Allow ~10s tolerance
        client.close()

    def test_retry_after_past_date_returns_zero(self):
        from datetime import datetime, timedelta, timezone

        client = HTTPClient(rate_limit=None)
        past = datetime.now(timezone.utc) - timedelta(seconds=60)
        date_str = past.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp = self._make_response({"Retry-After": date_str})
        wait = client._calculate_backoff(0, resp)
        assert wait == 0.0
        client.close()

    def test_retry_after_invalid_falls_back_to_exponential(self):
        client = HTTPClient(rate_limit=None)
        resp = self._make_response({"Retry-After": "not-a-date-or-number"})
        wait = client._calculate_backoff(2, resp)
        expected = 0.5 * (2**2)
        assert expected * 0.8 <= wait <= expected * 1.2
        client.close()

    def test_no_retry_after_uses_exponential(self):
        client = HTTPClient(rate_limit=None)
        resp = self._make_response({})
        wait = client._calculate_backoff(3, resp)
        expected = 0.5 * (2**3)
        assert expected * 0.8 <= wait <= expected * 1.2
        client.close()

    def test_jitter_varies(self):
        """Test that consecutive calls produce different wait times."""
        client = HTTPClient(rate_limit=None)
        resp = self._make_response({})
        waits = [client._calculate_backoff(2, resp) for _ in range(10)]
        assert len(set(waits)) > 1, "Backoff should vary due to jitter"
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
