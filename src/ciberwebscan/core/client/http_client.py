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
import random
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from ciberwebscan.config.loader import get_config

logger = logging.getLogger(__name__)

# Type alias for metrics callback
MetricsCallback = Callable[[str, str, int, float], None]


class RateLimiter:
    """
    Token bucket rate limiter per domain with optional AIMD adaptive control.

    When adaptive=False (legacy mode), uses a fixed rate limit per domain.
    When adaptive=True, adjusts the effective request rate dynamically based
    on server responses using the AIMD (Additive Increase / Multiplicative
    Decrease) pattern, independently per domain:

    - 429 Too Many Requests  -> multiplicative decrease (decrease_factor)
    - 5xx Server Error      -> severe decrease (decrease_factor * 0.5)
    - 2xx Success            -> additive increase (+increase_factor)
                               paused during latency spikes

    Thread-safe: all rate mutations are protected by a lock.
    """

    def __init__(
        self,
        requests_per_second: float = 5.0,
        *,
        adaptive: bool = False,
        min_rate: float = 0.5,
        increase_factor: float = 0.5,
        decrease_factor: float = 0.5,
        latency_spike_factor: float = 1.5,
        latency_window: int = 10,
        initial_rate: float | None = None,
    ):
        """
        Initialize the rate limiter.

        Args:
            requests_per_second: Max requests per second (ceiling). Default 5.0.
            adaptive: Enable AIMD adaptive rate control. Default False.
            min_rate: Minimum allowed rate (floor). Default 0.5.
            increase_factor: Additive increase per successful response. Default 0.5.
            decrease_factor: Multiplicative decrease on 429. Default 0.5.
            latency_spike_factor: Multiplier above avg latency to pause increase.
                Default 1.5 (50% above average).
            latency_window: Number of recent latencies to track per domain. Default 10.
            initial_rate: Starting rate per domain (defaults to requests_per_second).
        """
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")

        self._max_rate = requests_per_second
        self._adaptive = adaptive
        self._min_rate = min_rate
        self._increase_factor = increase_factor
        self._decrease_factor = decrease_factor
        self._latency_spike_factor = latency_spike_factor
        self._latency_window = latency_window

        self._initial_rate: float = (
            initial_rate if initial_rate is not None else requests_per_second
        )
        if self._initial_rate <= 0:
            raise ValueError("initial_rate must be > 0")

        # Thread-safe dynamic state
        self._lock = threading.Lock()
        self._current_rate: dict[str, float] = {}  # per-domain, lazy init

        # Per-domain state (protected by _lock)
        self._last_request: dict[str, float] = {}
        self._recent_latencies: dict[str, deque[float]] = {}

    def _rate_for(self, domain: str) -> float:
        """
        Return the current effective rate for *domain*, initialising on first use.

        MUST be called with ``self._lock`` held.
        """
        return self._current_rate.setdefault(domain, self._initial_rate)

    def wait(self, domain: str) -> float:
        """
        Wait if necessary to respect rate limit for domain.

        Thread-safe: reads/writes per-domain state under lock. Records the
        *reserved target slot* rather than the pre-sleep timestamp, so the
        invariant holds even though the actual sleep happens outside the lock.

        Args:
            domain: The domain to rate limit.

        Returns:
            Time waited in seconds (0 if no wait needed).
        """
        with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / self._rate_for(domain)
            last_slot = self._last_request.get(domain)
            target = last_slot + min_interval if last_slot is not None else now
            target = max(target, now)
            waited = target - now
            self._last_request[domain] = target

        if waited > 0:
            time.sleep(waited)

        return waited

    def on_response(self, status_code: int, response_time: float, domain: str) -> None:
        """
        Adjust the effective rate for *domain* based on a server response.

        Implements AIMD (Additive Increase / Multiplicative Decrease):
        - 429: rate *= decrease_factor  (e.g. 50% cut)
        - 5xx: rate *= decrease_factor * 0.5  (e.g. 75% cut — severe)
        - 2xx: rate += increase_factor  (additive growth, unless latency spike)

        This method is a no-op when adaptive=False.

        Args:
            status_code: HTTP status code of the response.
            response_time: Duration of the request in seconds.
            domain: The domain that was requested.
        """
        if not self._adaptive:
            return

        with self._lock:
            rate = self._rate_for(domain)
            if status_code == 429:
                rate = max(self._min_rate, rate * self._decrease_factor)
            elif status_code >= 500:
                rate = max(self._min_rate, rate * self._decrease_factor * 0.5)
            elif 200 <= status_code < 300 and not self._is_latency_spike(
                domain,
                response_time,
            ):
                rate = min(self._max_rate, rate + self._increase_factor)
            self._current_rate[domain] = rate

    def _is_latency_spike(self, domain: str, response_time: float) -> bool:
        """
        Return True if response_time is significantly above the recent average.

        A latency spike signals possible server congestion. The rate increase
        is paused during spikes but resumes once latencies normalise.
        """
        if domain not in self._recent_latencies:
            self._recent_latencies[domain] = deque(maxlen=self._latency_window)

        lats = self._recent_latencies[domain]

        if len(lats) < 3:
            lats.append(response_time)
            return False

        avg = sum(lats) / len(lats)
        lats.append(response_time)
        return response_time > avg * self._latency_spike_factor

    def clear(self, domain: str | None = None) -> None:
        """
        Clear rate limit state for a domain or all domains.

        Args:
            domain: Specific domain to clear, or None to clear all.
        """
        with self._lock:
            if domain:
                self._current_rate.pop(domain, None)
                self._last_request.pop(domain, None)
                self._recent_latencies.pop(domain, None)
            else:
                self._current_rate.clear()
                self._last_request.clear()
                self._recent_latencies.clear()

    def current_rate(self, domain: str) -> float:
        """
        Return the current effective rate for *domain*.

        For domains never seen, returns the initial configured rate.
        Thread-safe: takes the lock for the duration of the read.

        Args:
            domain: The domain to query.

        Returns:
            Current requests-per-second for that domain.
        """
        with self._lock:
            return self._rate_for(domain)

    @property
    def max_rate(self) -> float:
        """Maximum configured rate (ceiling)."""
        return self._max_rate


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

    # Default fallback when config is not available
    DEFAULT_RETRYABLE_STATUS_CODES: set[int] = {429, 500, 502, 503, 504}

    def __init__(
        self,
        timeout: float | None = None,
        max_retries: int | None = None,
        backoff_factor: float | None = None,
        rate_limit: float | None = None,
        http2: bool | None = None,
        verify: bool | None = None,
        follow_redirects: bool | None = None,
        default_headers: dict[str, str] | None = None,
        metrics_callback: MetricsCallback | None = None,
        proxy: str | None = None,
        retryable_status_codes: set[int] | None = None,
        max_redirects: int | None = None,
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
            retryable_status_codes: HTTP status codes that trigger retry.
                If None, uses config value or DEFAULT_RETRYABLE_STATUS_CODES.
            max_redirects: Maximum number of redirects to follow.
                If None, uses config value (default 10).
        """
        config = get_config().http

        resolved_timeout: float | httpx.Timeout
        if timeout is None:
            resolved_timeout = httpx.Timeout(
                connect=config.timeout.connect,
                read=config.timeout.read,
                write=config.timeout.write,
                pool=config.timeout.pool,
            )
        else:
            resolved_timeout = timeout

        resolved_max_retries = (
            config.retry.max_attempts if max_retries is None else max_retries
        )
        if resolved_max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        resolved_backoff_factor = (
            config.retry.backoff_factor if backoff_factor is None else backoff_factor
        )
        if resolved_backoff_factor < 0.1:
            raise ValueError("backoff_factor must be >= 0.1")
        resolved_rate_limit = (
            config.rate_limit.requests_per_second
            if rate_limit is None and config.rate_limit.per_domain
            else rate_limit
        )
        resolved_http2 = config.http2 if http2 is None else http2
        resolved_verify = config.verify_ssl if verify is None else verify
        resolved_follow_redirects = (
            config.follow_redirects if follow_redirects is None else follow_redirects
        )
        resolved_max_redirects = (
            config.max_redirects if max_redirects is None else max_redirects
        )

        resolved_proxy = proxy
        if resolved_proxy is None and config.proxy is not None:
            resolved_proxy = (
                str(config.proxy.https)
                if config.proxy.https
                else str(config.proxy.http)
                if config.proxy.http
                else config.proxy.socks5
            )

        self._proxy = resolved_proxy
        self._max_retries = resolved_max_retries
        self._backoff_factor = resolved_backoff_factor
        self._metrics_callback = metrics_callback

        # Retryable status codes: explicit param > config > class default
        if retryable_status_codes is not None:
            self._retryable_status_codes = retryable_status_codes
        elif config.retry.retryable_status_codes:
            self._retryable_status_codes = set(config.retry.retryable_status_codes)
        else:
            self._retryable_status_codes = self.DEFAULT_RETRYABLE_STATUS_CODES

        # Rate limiter (optional)
        self._rate_limiter = (
            RateLimiter(
                resolved_rate_limit,
                adaptive=config.rate_limit.adaptive,
                min_rate=config.rate_limit.min_rate,
                increase_factor=config.rate_limit.increase_factor,
                decrease_factor=config.rate_limit.decrease_factor,
                latency_spike_factor=config.rate_limit.latency_spike_factor,
                latency_window=config.rate_limit.latency_window,
            )
            if resolved_rate_limit
            else None
        )

        # Build httpx client
        self._client = httpx.Client(
            timeout=resolved_timeout,
            http2=resolved_http2,
            verify=resolved_verify,
            follow_redirects=resolved_follow_redirects,
            max_redirects=resolved_max_redirects,
            headers=default_headers,
            proxy=resolved_proxy,
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

        Each attempt applies rate limiting and feeds the adaptive AIMD
        algorithm, so the rate limiter sees every response (including
        intermediate 429/5xx that trigger retries).

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL.
            retry: Whether to retry on failure. Default True.
            **kwargs: Additional arguments passed to httpx.Client.request()
                Common: params, json, data, headers, cookies, files

        Returns:
            httpx.Response object (may be a retryable error response
            if all retries are exhausted — caller should check status_code).

        Raises:
            httpx.TimeoutException: If all retry attempts timeout.
            httpx.ConnectError: If connection fails after all retries.
            httpx.ReadError: If the server closes the connection mid-transfer.
            httpx.WriteError: If sending the request body fails.
            httpx.ProtocolError: If the server returns a malformed response.
            httpx.ProxyError: If communication with the proxy fails.
            httpx.HTTPStatusError: If raise_for_status() is called and fails.

        Note: All ``httpx.RequestError`` subclasses (network/transport errors)
        are caught and retried. Only non-retryable errors (e.g. invalid URLs,
            malformed arguments) will propagate immediately.
        """
        domain = urlparse(url).netloc
        if not domain:
            raise ValueError(
                f"Invalid URL: must include a hostname (got: {url!r})",
            )

        # Determine max attempts
        max_attempts = (self._max_retries + 1) if retry else 1
        last_exception: Exception | None = None
        response: httpx.Response | None = None

        for attempt in range(max_attempts):
            # rate-limit EVERY attempt, not just the first
            if self._rate_limiter:
                wait_time = self._rate_limiter.wait(domain)
                if wait_time > 0:
                    logger.debug(
                        f"Rate limited: waited {wait_time:.3f}s for {domain} "
                        f"(attempt {attempt + 1}/{max_attempts})",
                    )

            # measure only the actual request, not retries/backoff
            request_start = time.monotonic()
            try:
                response = self._client.request(method, url, **kwargs)
                request_duration = time.monotonic() - request_start

                # feed AIMD + log on EVERY response
                if self._rate_limiter:
                    self._rate_limiter.on_response(
                        response.status_code,
                        request_duration,
                        domain,
                    )
                self._log_request(
                    method,
                    url,
                    response.status_code,
                    request_duration,
                )

                # Check if we should retry based on status code
                if (
                    retry
                    and response.status_code in self._retryable_status_codes
                    and attempt < max_attempts - 1
                ):
                    wait_time = self._calculate_backoff(attempt, response)
                    logger.warning(
                        f"Retryable status {response.status_code} from {url}, "
                        f"attempt {attempt + 1}/{max_attempts}, "
                        f"waiting {wait_time:.2f}s"
                    )
                    time.sleep(wait_time)
                    continue

                return response

            except httpx.RequestError as e:
                last_exception = e
                request_duration = time.monotonic() - request_start

                # Feed AIMD: network failure = severe decrease (like 503)
                if self._rate_limiter:
                    self._rate_limiter.on_response(503, request_duration, domain)
                self._log_request(method, url, 0, request_duration)

                logger.warning(
                    f"Request failed: {type(e).__name__} for {url}, "
                    f"attempt {attempt + 1}/{max_attempts}"
                )

                if attempt < max_attempts - 1:
                    wait_time = self._backoff_factor * (2**attempt)
                    time.sleep(wait_time)
                else:
                    logger.error(
                        f"Request failed after {max_attempts} attempts: {url}",
                    )

        # All retries exhausted
        if last_exception:
            raise last_exception

        # Should not reach here, but return last response if we do
        assert response is not None
        return response

    def _calculate_backoff(self, attempt: int, response: httpx.Response) -> float:
        """
        Calculate backoff time, respecting Retry-After header if present.

        Supports both formats per RFC 9110:
        - Seconds (e.g. ``120``)
        - HTTP-date (e.g. ``Fri, 31 Dec 1999 23:59:59 GMT``)

        Falls back to exponential backoff if the header is missing or
        cannot be parsed.

        Args:
            attempt: Current attempt number (0-indexed).
            response: HTTP response (may contain Retry-After header).

        Returns:
            Time to wait in seconds.
        """
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            # Try integer seconds first
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass

            # Try HTTP-date format (RFC 2822 / RFC 9110)
            try:
                dt = parsedate_to_datetime(retry_after)
                now = datetime.now(timezone.utc)
                wait = (dt - now).total_seconds()
                return max(0.0, wait)
            except (ValueError, TypeError):
                pass

        # Exponential backoff with jitter to avoid thundering herd
        wait = self._backoff_factor * (2**attempt)
        wait *= random.uniform(0.8, 1.2)
        return max(0.0, wait)

    def _log_request(
        self,
        method: str,
        url: str,
        status_code: int,
        duration: float,
    ) -> None:
        """
        Log request completion and call metrics callback.

        Args:
            method: HTTP method used.
            url: Request URL.
            status_code: HTTP status code (0 for connection failures).
            duration: Request duration in seconds (pre-computed by caller).
        """

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
_default_client_lock = threading.Lock()


def get_client() -> HTTPClient:
    """Get or create the default HTTP client (thread-safe singleton)."""
    global _default_client
    if _default_client is None:
        with _default_client_lock:
            if _default_client is None:
                _default_client = HTTPClient()
    return _default_client


def get(url: str, **kwargs: Any) -> httpx.Response:
    """Convenience function for GET requests using default client."""
    return get_client().get(url, **kwargs)


def post(url: str, **kwargs: Any) -> httpx.Response:
    """Convenience function for POST requests using default client."""
    return get_client().post(url, **kwargs)
