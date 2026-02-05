"""
Default configuration values for CiberWebScan.

These defaults are used when no config file is provided or when
specific values are not set.
"""

from __future__ import annotations

from typing import Any

# =============================================================================
# Default Configuration Dictionary
# =============================================================================

DEFAULTS: dict[str, Any] = {
    # HTTP Client
    "http": {
        "timeout": {
            "connect": 10.0,
            "read": 30.0,
            "write": 30.0,
            "pool": 10.0,
        },
        "retry": {
            "max_attempts": 3,
            "backoff_factor": 0.5,
            "retryable_status_codes": [429, 500, 502, 503, 504],
        },
        "rate_limit": {
            "requests_per_second": 5.0,
            "per_domain": True,
        },
        "proxy": None,
        "http2": True,
        "follow_redirects": True,
        "max_redirects": 10,
        "verify_ssl": True,
    },
    # User Agent
    "user_agent": {
        "mode": "rotate",
        "custom": None,
        "rotate_interval": 10,
    },
    # Scraping
    "scraping": {
        "dynamic": {
            "enabled": False,
            "wait_timeout": 10.0,
            "wait_for_selector": None,
            "headless": True,
            "browser": "chrome",
        },
        "pagination": {
            "enabled": False,
            "max_pages": 10,
            "next_selector": None,
            "page_param": None,
        },
        "extract_links": True,
        "extract_images": True,
        "extract_scripts": True,
        "extract_forms": True,
        "max_content_length": 10 * 1024 * 1024,
    },
    # Analysis
    "analysis": {
        "ssl": {
            "check_expiry": True,
            "check_chain": True,
            "min_protocol": "TLSv1.2",
        },
        "fingerprint": {
            "deep_scan": False,
            "check_headers": True,
            "check_cookies": True,
            "check_html": True,
        },
        "cve": {
            "sources": ["nvd"],
            "cache_ttl": 86400,
            "max_results": 100,
        },
    },
    # Export
    "export": {
        "format": "json",
        "pretty": True,
        "include_raw": False,
        "output_dir": "exports",
    },
    # Cache
    "cache": {
        "enabled": True,
        "ttl": 3600,
        "max_size": 1000,
        "backend": "memory",
    },
    # Logging
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": None,
    },
}


def get_default(key: str, default: Any = None) -> Any:
    """
    Get a default value by dot-notation key.

    Args:
        key: Configuration key (e.g., 'http.timeout.connect').
        default: Value to return if key not found.

    Returns:
        The default value or the provided default.
    """
    parts = key.split(".")
    current: Any = DEFAULTS

    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default

    return current
