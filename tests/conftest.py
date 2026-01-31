"""
Shared pytest fixtures for CiberWebScan tests.
"""

import pytest


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
