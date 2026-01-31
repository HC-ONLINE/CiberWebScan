"""
Proxy utilities for HTTP requests.

Provides validation, parsing, rotation, and connectivity checking for HTTP/HTTPS proxies.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ciberwebscan.core.client.http_client import HTTPClient

logger = logging.getLogger(__name__)

# Regex pattern for proxy URL validation
# Matches: http(s)://[user:pass@]host[:port]
PROXY_REGEX = re.compile(
    r"^(http|https|socks5)://([^:@\s]+(:[^@\s]+)?@)?([\w\.-]+)(:\d+)?$"
)

# Private IP patterns
PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\.\d+\.\d+\.\d+$"),  # Loopback
    re.compile(r"^10\.\d+\.\d+\.\d+$"),  # Class A private
    re.compile(r"^192\.168\.\d+\.\d+$"),  # Class C private
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$"),  # Class B private
]


class ProxyValidationError(ValueError):
    """Raised when proxy validation fails."""

    pass


@dataclass
class ProxyConfig:
    """Configuration for proxy behavior."""

    allow_local: bool = False
    allow_private: bool = False
    check_timeout: float = 5.0
    test_url: str = "https://httpbin.org/ip"


def is_private_ip(host: str) -> bool:
    """
    Check if a host is a private/local IP address.

    Args:
        host: Hostname or IP address to check.

    Returns:
        True if the host is a private/local address.
    """
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True

    return any(pattern.match(host) for pattern in PRIVATE_IP_PATTERNS)


def parse_proxy(
    proxy_str: str,
    *,
    allow_local: bool = False,
    allow_private: bool = False,
) -> str | None:
    """
    Validate and normalize a proxy string.

    Args:
        proxy_str: Proxy URL in format 'protocol://[user:pass@]host[:port]'.
        allow_local: Whether to allow localhost proxies.
        allow_private: Whether to allow private network proxies.

    Returns:
        Normalized proxy string if valid, None if empty.

    Raises:
        ProxyValidationError: If proxy format is invalid or not allowed.

    Examples:
        >>> parse_proxy('http://user:pass@proxy.example.com:8080')
        'http://user:pass@proxy.example.com:8080'
        >>> parse_proxy('')
        None
        >>> parse_proxy('http://127.0.0.1:8080')  # Raises if allow_local=False
        ProxyValidationError: Local proxies are not allowed
    """
    if not proxy_str or not proxy_str.strip():
        return None

    proxy_str = proxy_str.strip()

    # Add default scheme if missing
    if not proxy_str.startswith(("http://", "https://", "socks5://")):
        proxy_str = f"http://{proxy_str}"

    if not PROXY_REGEX.match(proxy_str):
        raise ProxyValidationError(
            f"Invalid proxy format: '{proxy_str}'. "
            "Expected: protocol://[user:pass@]host[:port]"
        )

    parsed = urlparse(proxy_str)
    host = parsed.hostname or ""

    # Check for local/private addresses
    if not allow_local and host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        raise ProxyValidationError(
            "Local proxies are not allowed. Set allow_local=True to override."
        )

    if not allow_private and is_private_ip(host):
        raise ProxyValidationError(
            "Private network proxies are not allowed. Set allow_private=True to override."
        )

    return proxy_str


def parse_proxy_list(
    proxy_list_str: str,
    *,
    allow_local: bool = False,
    allow_private: bool = False,
) -> list[str]:
    """
    Parse and validate a list of proxies from a string.

    Proxies can be separated by commas, newlines, or spaces.

    Args:
        proxy_list_str: String containing multiple proxies.
        allow_local: Whether to allow localhost proxies.
        allow_private: Whether to allow private network proxies.

    Returns:
        List of validated proxy strings.

    Raises:
        ProxyValidationError: If any proxy is invalid.

    Examples:
        >>> parse_proxy_list('http://p1:8080, http://p2:8080')
        ['http://p1:8080', 'http://p2:8080']
    """
    if not proxy_list_str:
        return []

    # Split by comma, newline, or whitespace
    raw_list = re.split(r"[\s,]+", proxy_list_str)
    proxies = []

    for proxy in raw_list:
        proxy = proxy.strip()
        if proxy:
            validated = parse_proxy(
                proxy,
                allow_local=allow_local,
                allow_private=allow_private,
            )
            if validated:
                proxies.append(validated)

    return proxies


def sanitize_proxy_for_display(proxy: str) -> str:
    """
    Remove credentials from proxy URL for safe display/logging.

    Args:
        proxy: Full proxy URL possibly containing credentials.

    Returns:
        Proxy URL with credentials removed (host:port only).

    Examples:
        >>> sanitize_proxy_for_display('http://user:pass@proxy.com:8080')
        'proxy.com:8080'
    """
    if not proxy:
        return ""

    # Remove everything before @ (credentials)
    if "@" in proxy:
        proxy = proxy.split("@")[-1]

    # Remove protocol
    for protocol in ("http://", "https://", "socks5://"):
        if proxy.startswith(protocol):
            proxy = proxy[len(protocol) :]
            break

    return proxy


async def check_proxy_connectivity(
    proxy: str,
    client: HTTPClient,
    test_url: str = "https://httpbin.org/ip",
    timeout: float = 5.0,
) -> bool:
    """
    Test if a proxy is working by making a request through it.

    Args:
        proxy: Proxy URL to test.
        client: HTTPClient instance to use for the test.
        test_url: URL to request through the proxy.
        timeout: Request timeout in seconds.

    Returns:
        True if proxy is working, False otherwise.
    """
    try:
        # Create a new client with this proxy
        from ciberwebscan.core.client.http_client import HTTPClient

        test_client = HTTPClient(
            timeout=timeout,
            max_retries=1,
            proxy=proxy,
        )

        with test_client:
            response = test_client.head(test_url)
            return response.status_code < 400

    except Exception as e:
        logger.debug(f"Proxy {sanitize_proxy_for_display(proxy)} failed: {e}")
        return False


def check_proxy_connectivity_sync(
    proxy: str,
    test_url: str = "https://httpbin.org/ip",
    timeout: float = 5.0,
) -> bool:
    """
    Synchronous version of proxy connectivity check.

    Args:
        proxy: Proxy URL to test.
        test_url: URL to request through the proxy.
        timeout: Request timeout in seconds.

    Returns:
        True if proxy is working, False otherwise.
    """
    try:
        import httpx

        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            response = client.head(test_url)
            return response.status_code < 400

    except Exception as e:
        logger.debug(f"Proxy {sanitize_proxy_for_display(proxy)} failed: {e}")
        return False


def filter_working_proxies(
    proxies: list[str],
    test_url: str = "https://httpbin.org/ip",
    timeout: float = 5.0,
) -> tuple[list[str], list[str]]:
    """
    Filter a list of proxies by connectivity.

    Args:
        proxies: List of proxy URLs to test.
        test_url: URL to use for testing.
        timeout: Timeout for each test.

    Returns:
        Tuple of (working_proxies, failed_proxies).

    Examples:
        >>> working, failed = filter_working_proxies(['http://p1:8080', 'http://p2:8080'])
    """
    working = []
    failed = []

    for proxy in proxies:
        if check_proxy_connectivity_sync(proxy, test_url, timeout):
            working.append(proxy)
            logger.debug(f"Proxy {sanitize_proxy_for_display(proxy)} is working")
        else:
            failed.append(proxy)
            logger.debug(f"Proxy {sanitize_proxy_for_display(proxy)} failed")

    return working, failed


@dataclass
class ProxyRotator:
    """
    Round-robin proxy rotator.

    Cycles through a list of proxies, returning a different one on each call.
    Thread-safe for basic usage.

    Attributes:
        proxies: List of proxy URLs available for rotation.

    Examples:
        >>> rotator = ProxyRotator(['http://p1:8080', 'http://p2:8080'])
        >>> rotator.next()
        'http://p1:8080'
        >>> rotator.next()
        'http://p2:8080'
        >>> rotator.next()  # Wraps around
        'http://p1:8080'
    """

    proxies: list[str]
    _index: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate proxies list."""
        if not self.proxies:
            raise ValueError("Proxy list cannot be empty")

    def next(self) -> str:
        """
        Get the next proxy in rotation.

        Returns:
            Next proxy URL in the rotation sequence.
        """
        proxy = self.proxies[self._index]
        self._index = (self._index + 1) % len(self.proxies)
        return proxy

    def current(self) -> str:
        """
        Get the current proxy without advancing.

        Returns:
            Current proxy URL.
        """
        return self.proxies[self._index]

    def reset(self) -> None:
        """Reset rotation to the first proxy."""
        self._index = 0

    def remove(self, proxy: str) -> bool:
        """
        Remove a proxy from the rotation.

        Useful for removing failed proxies.

        Args:
            proxy: Proxy URL to remove.

        Returns:
            True if proxy was removed, False if not found.

        Raises:
            ValueError: If removing the last proxy.
        """
        if proxy in self.proxies:
            if len(self.proxies) == 1:
                raise ValueError("Cannot remove the last proxy")

            idx = self.proxies.index(proxy)
            self.proxies.remove(proxy)

            # Adjust index if needed
            if self._index >= len(self.proxies):
                self._index = 0
            elif idx < self._index:
                self._index -= 1

            return True
        return False

    def add(self, proxy: str) -> None:
        """
        Add a new proxy to the rotation.

        Args:
            proxy: Proxy URL to add.
        """
        if proxy not in self.proxies:
            self.proxies.append(proxy)

    def __len__(self) -> int:
        """Return the number of proxies in rotation."""
        return len(self.proxies)

    def __iter__(self):
        """Iterate over all proxies."""
        return iter(self.proxies)
