"""
Tests for the shared client IP resolver.

Covers peer fallback, the trusted-proxy policy, right-to-left chain
resolution, malformed hops, and IPv4/IPv6/CIDR/IPv4-mapped handling.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from starlette.requests import Request

from ciberwebscan.api.client_ip import resolve_client_ip
from ciberwebscan.config.models import APIConfig, AppConfig

pytestmark = pytest.mark.unit

# =============================================================================
# Helpers
# =============================================================================


def _request(
    peer: tuple[str, int] | None = None,
    forwarded_for: str | None = None,
    extra_forwarded_lines: list[str] | None = None,
) -> Request:
    """Build a bare ASGI Request with an explicit peer and XFF chain."""
    headers: list[tuple[bytes, bytes]] = []
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode()))
    for line in extra_forwarded_lines or []:
        headers.append((b"x-forwarded-for", line.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "client": peer,
    }
    return Request(scope)


def _with_config(config: AppConfig):
    return patch("ciberwebscan.api.client_ip.get_config", return_value=config)


def _trusted(*entries: str) -> AppConfig:
    return AppConfig(api=APIConfig(trusted_proxies=list(entries)))


# =============================================================================
# Peer Fallback / Secure Default
# =============================================================================


class TestPeerFallback:
    """Without trusted proxies the peer is the only identity."""

    def test_peer_without_forwarded_for(self):
        assert resolve_client_ip(_request(("10.0.0.1", 50000))) == "10.0.0.1"

    def test_forwarded_for_ignored_with_default_config(self):
        request = _request(("10.0.0.1", 50000), "203.0.113.7")
        with _with_config(AppConfig()):
            assert resolve_client_ip(request) == "10.0.0.1"

    def test_empty_forwarded_for_header(self):
        request = _request(("10.0.0.1", 50000), "")
        assert resolve_client_ip(request) == "10.0.0.1"

    def test_whitespace_only_forwarded_for_header(self):
        request = _request(("10.0.0.1", 50000), "   ")
        assert resolve_client_ip(request) == "10.0.0.1"

    def test_missing_client_scope_falls_back_to_unknown(self):
        request = _request(None, "203.0.113.7")
        assert resolve_client_ip(request) == "unknown"

    def test_unparseable_peer_never_trusts_forwarded_for(self):
        request = _request(("testclient", 50000), "203.0.113.7")
        assert resolve_client_ip(request) == "unknown"

    def test_empty_peer_host_falls_back_to_unknown(self):
        request = _request(("", 50000), "203.0.113.7")
        assert resolve_client_ip(request) == "unknown"


# =============================================================================
# Trusted Proxy Policy
# =============================================================================


class TestTrustedProxyPolicy:
    """X-Forwarded-For is honoured only for declared proxy peers."""

    def test_empty_peer_ignores_header_even_when_list_configured(self):
        """A missing peer address collapses to the shared 'unknown' bucket."""
        request = _request(("", 50000), "203.0.113.7")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "unknown"

    def test_peer_outside_configured_list_is_not_trusted(self):
        request = _request(("192.168.9.9", 50000), "203.0.113.7")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "192.168.9.9"

    def test_cidr_entry_matches_peer_inside_range(self):
        request = _request(("10.4.5.6", 50000), "203.0.113.7")
        with _with_config(_trusted("10.0.0.0/8")):
            assert resolve_client_ip(request) == "203.0.113.7"

    def test_cidr_entry_rejects_peer_outside_range(self):
        request = _request(("11.4.5.6", 50000), "203.0.113.7")
        with _with_config(_trusted("10.0.0.0/8")):
            assert resolve_client_ip(request) == "11.4.5.6"

    def test_ipv6_cidr_entry_matches_peer_inside_range(self):
        request = _request(("2001:db8::7", 50000), "203.0.113.7")
        with _with_config(_trusted("2001:db8::/32")):
            assert resolve_client_ip(request) == "203.0.113.7"

    def test_ipv6_cidr_entry_rejects_peer_outside_range(self):
        request = _request(("2001:db9::7", 50000), "203.0.113.7")
        with _with_config(_trusted("2001:db8::/32")):
            assert resolve_client_ip(request) == "2001:db9::7"

    def test_trusted_peer_without_header_keeps_peer(self):
        request = _request(("10.0.0.50", 50000))
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "10.0.0.50"

    def test_invalid_config_entries_are_ignored_at_runtime(self):
        """Fail closed if an invalid entry reaches the resolver."""
        broken = SimpleNamespace(api=SimpleNamespace(trusted_proxies=["garbage"]))
        with patch("ciberwebscan.api.client_ip.get_config", return_value=broken):
            request = _request(("10.0.0.9", 50000), "203.0.113.7")
            assert resolve_client_ip(request) == "10.0.0.9"


# =============================================================================
# Chain Resolution (right to left)
# =============================================================================


class TestChainResolution:
    """Validated traversal from the nearest hop towards the client."""

    def test_rightmost_untrusted_hop_is_the_client(self):
        request = _request(("10.0.0.50", 50000), "1.1.1.1, 2.2.2.2")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "2.2.2.2"

    def test_trusted_hops_are_skipped(self):
        request = _request(("10.0.0.50", 50000), "203.0.113.5, 10.0.0.49, 10.0.0.48")
        with _with_config(_trusted("10.0.0.50", "10.0.0.49", "10.0.0.48")):
            assert resolve_client_ip(request) == "203.0.113.5"

    def test_fully_trusted_chain_returns_leftmost_trusted_hop(self):
        request = _request(("10.0.0.50", 50000), "10.0.0.5, 10.0.0.6")
        with _with_config(_trusted("10.0.0.50", "10.0.0.5", "10.0.0.6")):
            assert resolve_client_ip(request) == "10.0.0.5"

    def test_malformed_hop_stops_the_walk(self):
        """A bad hop never routes the walk into client-controlled data."""
        request = _request(("10.0.0.50", 50000), "1.1.1.1, garbage")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "10.0.0.50"

    def test_empty_entry_stops_the_walk(self):
        request = _request(("10.0.0.50", 50000), "1.1.1.1, ")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "10.0.0.50"

    def test_port_suffixed_hop_is_malformed(self):
        request = _request(("10.0.0.50", 50000), "1.1.1.1, 10.0.0.5:8080")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "10.0.0.50"

    def test_duplicate_header_lines_are_joined(self):
        """Starlette exposes repeated XFF lines via getlist; join them.

        The forged identity sits on the first line only: a get()-based
        resolver would return the trusted hop 10.0.0.49 instead.
        """
        request = _request(
            ("10.0.0.50", 50000),
            forwarded_for="10.0.0.49",
            extra_forwarded_lines=["203.0.113.5"],
        )
        with _with_config(_trusted("10.0.0.50", "10.0.0.49")):
            assert resolve_client_ip(request) == "203.0.113.5"


# =============================================================================
# Address Families / Normalization
# =============================================================================


class TestAddressFamilies:
    """IPv4, IPv6, CIDR and IPv4-mapped addresses behave consistently."""

    def test_ipv6_peer(self):
        request = _request(("::1", 50000), "2001:db8::1")
        assert resolve_client_ip(request) == "::1"

    def test_ipv6_trusted_proxy_resolves_ipv6_client(self):
        request = _request(("::1", 50000), "2001:db8::5, ::1")
        with _with_config(_trusted("::1")):
            assert resolve_client_ip(request) == "2001:db8::5"

    def test_ipv4_mapped_peer_is_normalized(self):
        request = _request(("::ffff:10.0.0.9", 50000))
        assert resolve_client_ip(request) == "10.0.0.9"

    def test_ipv4_mapped_peer_matches_ipv4_cidr(self):
        request = _request(("::ffff:10.0.0.9", 50000), "8.8.8.8")
        with _with_config(_trusted("10.0.0.0/8")):
            assert resolve_client_ip(request) == "8.8.8.8"

    def test_ipv4_mapped_hop_is_normalized(self):
        request = _request(("10.0.0.50", 50000), "2.2.2.2, ::ffff:8.8.8.8")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "8.8.8.8"

    def test_ipv6_hop_is_not_matched_against_ipv4_network(self):
        request = _request(("10.0.0.50", 50000), "2001:db8::1")
        with _with_config(_trusted("10.0.0.50")):
            assert resolve_client_ip(request) == "2001:db8::1"


# =============================================================================
# Default Config Contract
# =============================================================================


class TestDefaultConfiguration:
    """The shipped configuration must be the safe one."""

    def test_trusted_proxies_default_is_empty(self):
        assert AppConfig().api.trusted_proxies == []

    def test_default_config_ignores_forwarded_for(self):
        request = _request(("10.0.0.9", 50000), "203.0.113.7")
        with _with_config(AppConfig()):
            assert resolve_client_ip(request) == "10.0.0.9"
