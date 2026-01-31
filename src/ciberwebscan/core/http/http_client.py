# core/http/client.py
"""
Lightweight HTTP client with retry, rate limiting, and telemetry.

This module provides a thin wrapper around httpx that adds:
- Automatic retry with exponential backoff
- Global rate limiting per domain
- Structured logging for all requests
- Metrics/telemetry hooks

The wrapper is intentionally minimal to avoid the overhead
of a full compatibility layer while centralizing cross-cutting concerns.
"""

import logging
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Type alias for metrics callback
MetricsCallback = Callable[[str, str, int, float], None]


class RateLimiter:
    """
    Token bucket rate limiter per domain.

    Ensures requests to the same domain respect the configured rate limit,
    preventing API throttling and being a good citizen.

    Attributes:
        requests_per_second: Maximum requests per second per domain.
    """

    def __init__(self, requests_per_second: float = 5.0):
        """
        Initialize the rate limiter.

        Args:
            requests_per_second: Max requests per second. Default 5.0.
        """
        self._last_request: dict[str, float] = {}
        self._min_interval = 1.0 / requests_per_second

    def wait(self, domain: str) -> float:
        """
        Wait if necessary to respect rate limit for domain.

        Args:
            domain: The domain to rate limit.

        Returns:
            Time waited in seconds (0 if no wait needed).
        """
        now = time.monotonic()
        waited = 0.0

        if domain in self._last_request:
            elapsed = now - self._last_request[domain]
            if elapsed < self._min_interval:
                waited = self._min_interval - elapsed
                time.sleep(waited)

        self._last_request[domain] = time.monotonic()
        return waited

    def clear(self, domain: str | None = None) -> None:
        """
        Clear rate limit state for a domain or all domains.

        Args:
            domain: Specific domain to clear, or None to clear all.
        """
        if domain:
            self._last_request.pop(domain, None)
        else:
            self._last_request.clear()


class HTTPClient:
    """
    HTTP client with automatic retry, rate limiting, and logging.

    This is a lightweight wrapper around httpx.Client that centralizes:
    - Retry logic with exponential backoff
    - Per-domain rate limiting
    - Structured request/response logging
    - Metrics collection hooks

    Example:
        >>> client = HTTPClient(max_retries=3, rate_limit=2.0)
        >>> response = client.get("https://example.com/api")
        >>> response.status_code
        200

        >>> with HTTPClient() as client:
        ...     data = client.get("https://api.example.com").json()
    """

    # Status codes that should trigger a retry
    RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        rate_limit: float | None = None,
        http2: bool = True,
        verify: bool = True,
        follow_redirects: bool = True,
        default_headers: dict[str, str] | None = None,
        metrics_callback: MetricsCallback | None = None,
        proxy: str | None = None,
    ):
        """
        Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds. Default 30.0.
            max_retries: Maximum retry attempts on failure. Default 3.
            backoff_factor: Multiplier for exponential backoff. Default 0.5.
                Wait time = backoff_factor * (2 ** attempt)
                With default: 0.5s, 1s, 2s, 4s...
            rate_limit: Max requests per second per domain. None to disable.
            http2: Enable HTTP/2 support. Default True.
            verify: Verify SSL certificates. Default True.
            follow_redirects: Follow HTTP redirects. Default True.
            default_headers: Headers to include in all requests.
            metrics_callback: Optional callback for metrics collection.
                Signature: (method, url, status_code, duration_seconds) -> None
            proxy: Optional proxy URL (e.g., 'http://user:pass@host:port').
                Supports http, https, and socks5 protocols.
        """
        self._proxy = proxy
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._metrics_callback = metrics_callback

        # Rate limiter (optional)
        self._rate_limiter = RateLimiter(rate_limit) if rate_limit else None

        # Build httpx client
        self._client = httpx.Client(
            timeout=timeout,
            http2=http2,
            verify=verify,
            follow_redirects=follow_redirects,
            headers=default_headers,
            proxy=proxy,
        )

    def request(
        self,
        method: str,
        url: str,
        retry: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Perform an HTTP request with retry and rate limiting.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL.
            retry: Whether to retry on failure. Default True.
            **kwargs: Additional arguments passed to httpx.Client.request()
                Common: params, json, data, headers, cookies, files

        Returns:
            httpx.Response object.

        Raises:
            httpx.TimeoutException: If all retry attempts timeout.
            httpx.ConnectError: If connection fails after all retries.
            httpx.HTTPStatusError: If raise_for_status() is called and fails.
        """
        domain = urlparse(url).netloc
        start_time = time.monotonic()

        # Apply rate limiting
        if self._rate_limiter:
            wait_time = self._rate_limiter.wait(domain)
            if wait_time > 0:
                logger.debug(f"Rate limited: waited {wait_time:.3f}s for {domain}")

        # Determine max attempts
        max_attempts = (self._max_retries + 1) if retry else 1
        last_exception: Exception | None = None
        response: httpx.Response | None = None

        for attempt in range(max_attempts):
            try:
                response = self._client.request(method, url, **kwargs)

                # Check if we should retry based on status code
                if retry and response.status_code in self.RETRYABLE_STATUS_CODES:
                    if attempt < max_attempts - 1:
                        wait_time = self._calculate_backoff(attempt, response)
                        logger.warning(
                            f"Retryable status {response.status_code} from {url}, "
                            f"attempt {attempt + 1}/{max_attempts}, waiting {wait_time:.2f}s"
                        )
                        time.sleep(wait_time)
                        continue

                # Success - log and return
                self._log_request(method, url, response.status_code, start_time)
                return response

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_exception = e
                if attempt < max_attempts - 1:
                    wait_time = self._backoff_factor * (2**attempt)
                    logger.warning(
                        f"Request failed: {type(e).__name__} for {url}, "
                        f"attempt {attempt + 1}/{max_attempts}, waiting {wait_time:.2f}s"
                    )
                    time.sleep(wait_time)
                else:
                    logger.error(f"Request failed after {max_attempts} attempts: {url}")

        # All retries exhausted
        if last_exception:
            raise last_exception

        # Should not reach here, but return last response if we do
        assert response is not None
        return response

    def _calculate_backoff(self, attempt: int, response: httpx.Response) -> float:
        """
        Calculate backoff time, respecting Retry-After header if present.

        Args:
            attempt: Current attempt number (0-indexed).
            response: HTTP response (may contain Retry-After header).

        Returns:
            Time to wait in seconds.
        """
        # Check for Retry-After header
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass  # Not a number, use exponential backoff

        # Exponential backoff
        return self._backoff_factor * (2**attempt)

    def _log_request(
        self,
        method: str,
        url: str,
        status_code: int,
        start_time: float,
    ) -> None:
        """
        Log request completion and call metrics callback.

        Args:
            method: HTTP method used.
            url: Request URL.
            status_code: Response status code.
            start_time: Request start time (from time.monotonic()).
        """
        duration = time.monotonic() - start_time

        # Structured log
        logger.info(
            f"HTTP {method} {url} -> {status_code} ({duration:.3f}s)",
            extra={
                "http_method": method,
                "http_url": url,
                "http_status": status_code,
                "http_duration": duration,
            },
        )

        # Metrics callback
        if self._metrics_callback:
            try:
                self._metrics_callback(method, url, status_code, duration)
            except Exception as e:
                logger.warning(f"Metrics callback failed: {e}")

    # Convenience methods

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a PUT request."""
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a PATCH request."""
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a DELETE request."""
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a HEAD request."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send an OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)

    # Context manager support

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


# Module-level convenience functions using a default client
_default_client: HTTPClient | None = None


def get_client() -> HTTPClient:
    """Get or create the default HTTP client."""
    global _default_client
    if _default_client is None:
        _default_client = HTTPClient()
    return _default_client


def get(url: str, **kwargs: Any) -> httpx.Response:
    """Convenience function for GET requests using default client."""
    return get_client().get(url, **kwargs)


def post(url: str, **kwargs: Any) -> httpx.Response:
    """Convenience function for POST requests using default client."""
    return get_client().post(url, **kwargs)
