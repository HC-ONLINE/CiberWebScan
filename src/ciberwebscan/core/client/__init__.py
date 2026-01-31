"""
HTTP client module.

Provides HTTP client with retry, rate limiting, proxy and user-agent support.
"""

from ciberwebscan.core.client.http_client import HTTPClient, RateLimiter
from ciberwebscan.core.client.proxy import (
    ProxyConfig,
    ProxyRotator,
    ProxyValidationError,
    check_proxy_connectivity_sync,
    filter_working_proxies,
    parse_proxy,
    parse_proxy_list,
    sanitize_proxy_for_display,
)
from ciberwebscan.core.client.user_agent import (
    UserAgentProvider,
    UserAgentRotator,
    get_default_user_agents,
)

__all__ = [
    # Client
    "HTTPClient",
    "RateLimiter",
    # Proxy
    "ProxyConfig",
    "ProxyRotator",
    "ProxyValidationError",
    "parse_proxy",
    "parse_proxy_list",
    "sanitize_proxy_for_display",
    "check_proxy_connectivity_sync",
    "filter_working_proxies",
    # User-Agent
    "UserAgentProvider",
    "UserAgentRotator",
    "get_default_user_agents",
]
