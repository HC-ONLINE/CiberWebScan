"""
Shared pytest fixtures for CiberWebScan tests.
"""

from __future__ import annotations

import errno
import socket

import pytest

from ciberwebscan.config.loader import reset_config
from tests.network_guard import is_loopback_address

# DNS answers handed out by the fake resolver. 93.184.216.34 is a
# real public IP; never use TEST-NET ranges (198.51.100.x / 203.0.113.x)
# here because ipaddress classifies them as not global and the SSRF policy
# would block them.
_FAKE_DNS_DEFAULT = ["93.184.216.34"]
_FAKE_DNS_TABLE: dict[str, list[str]] = {
    "example.com": ["93.184.216.34"],
    "allowed.example.com": ["93.184.216.34"],
    "public.example.com": ["93.184.216.34"],
    # Hostnames that must resolve to loopback/metadata to prove that
    # DNS-based blocking works.
    "localtest.me": ["127.0.0.1"],
    "127.0.0.1.nip.io": ["127.0.0.1"],
    "metadata.google.internal": ["169.254.169.254"],
    # Deliberately unresolvable names (fail-closed behaviour).
    "nonexistent.invalid": [],
}
_FAKE_DNS_FAILURES = {"nonexistent.invalid"}


def _fake_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
    """Local stand-in for ``socket.getaddrinfo`` used by the SSRF resolver."""
    if host in _FAKE_DNS_FAILURES:
        raise socket.gaierror(f"Name or service not known: {host}")
    addresses = _FAKE_DNS_TABLE.get(host, _FAKE_DNS_DEFAULT)
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
        for address in addresses
    ]


@pytest.fixture(autouse=True)
def fake_dns_resolver(monkeypatch, request):
    """Resolve hostnames through a local table so unit tests never hit DNS.

    Tests marked ``network`` or ``external`` keep the real resolver. The
    SSRF policy cache is cleared before and after each test to avoid
    leaking resolutions across tests.
    """
    from ciberwebscan.core.client import ssrf as ssrf_module

    ssrf_module.clear_dns_cache()

    is_live = bool(
        request.node.get_closest_marker("network")
        or request.node.get_closest_marker("external")
    )
    if not is_live:
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    yield

    ssrf_module.clear_dns_cache()


@pytest.fixture(autouse=True)
def block_external_connections(monkeypatch, request):
    """Fail fast on accidental non-loopback TCP connections.

    Unit tests that build real services/clients can otherwise issue real
    HTTP requests (via ``HTTPClient``/httpx) to whatever the fake DNS
    resolver returns. On CI runners those destinations often blackhole,
    so the connect timeout plus ``HTTPClient`` retries turn a single
    accidental request into minutes of waiting.

    Tests marked ``network`` or ``external`` keep real connectivity;
    loopback (needed by local integration servers and TestClient) always
    stays allowed.
    """
    if request.node.get_closest_marker("network") or request.node.get_closest_marker(
        "external"
    ):
        yield
        return

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded_connect(sock, address):
        if not is_loopback_address(address):
            raise ConnectionRefusedError(
                errno.ECONNREFUSED,
                f"Blocked non-loopback connection to {address!r} "
                "(unit tests may not open external connections; "
                "mark the test with @pytest.mark.network or "
                "@pytest.mark.external if it is intentional)",
            )
        return original_connect(sock, address)

    def guarded_connect_ex(sock, address):
        if not is_loopback_address(address):
            return errno.ECONNREFUSED
        return original_connect_ex(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    yield


@pytest.fixture(autouse=True)
def isolate_global_config():
    """Reset the global config singleton before and after each test.

    ConfigService() shares the global loader (get_loader()), so tests that
    mutate configuration must not leak state into other tests.
    """
    reset_config()
    yield
    reset_config()


@pytest.fixture
def sample_user_agents() -> list[str]:
    """Sample user agents for testing."""
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 14) Chrome/120.0.0.0 Mobile",
    ]


@pytest.fixture
def sample_proxies() -> list[str]:
    """Sample proxy URLs for testing."""
    return [
        "http://proxy1.example.com:8080",
        "http://proxy2.example.com:8080",
        "http://user:pass@proxy3.example.com:3128",
    ]


@pytest.fixture
def valid_proxy_formats() -> list[str]:
    """Valid proxy URL formats for testing validation."""
    return [
        "http://proxy.com:8080",
        "https://proxy.com:443",
        "http://user:pass@proxy.com:8080",
        "socks5://proxy.com:1080",
    ]


@pytest.fixture
def invalid_proxy_formats() -> list[str]:
    """Invalid proxy URL formats for testing validation."""
    return [
        "",
        "not-a-url",
        "ftp://proxy.com:8080",  # Wrong scheme
        "http://",  # Missing host
        "://proxy.com:8080",  # Missing scheme
    ]
