"""
Unit tests for configuration models — proxy rotation fields, retry config,
rate limit config, and CORS config.
"""

import pytest
from pydantic import ValidationError

from ciberwebscan.config.models import (
    APIConfig,
    ProxyConfig,
    RateLimitConfig,
    RetryConfig,
)

pytestmark = pytest.mark.unit


class TestRetryConfig:
    """Tests for RetryConfig validation."""

    def test_default_values(self):
        cfg = RetryConfig()
        assert cfg.max_attempts == 3
        assert cfg.backoff_factor == 0.5
        assert cfg.retryable_status_codes == [429, 500, 502, 503, 504]

    def test_backoff_factor_zero_allowed(self):
        """backoff_factor=0 is valid (immediate retry, no delay)."""
        cfg = RetryConfig(backoff_factor=0.0)
        assert cfg.backoff_factor == 0.0

    def test_backoff_factor_negative_rejected(self):
        with pytest.raises(ValidationError):
            RetryConfig(backoff_factor=-0.1)

    def test_backoff_factor_max_allowed(self):
        cfg = RetryConfig(backoff_factor=10.0)
        assert cfg.backoff_factor == 10.0

    def test_backoff_factor_above_max_rejected(self):
        with pytest.raises(ValidationError):
            RetryConfig(backoff_factor=10.1)

    def test_max_attempts_zero_rejected(self):
        with pytest.raises(ValidationError):
            RetryConfig(max_attempts=0)


class TestRateLimitConfig:
    """Tests for RateLimitConfig validation."""

    def test_default_values(self):
        cfg = RateLimitConfig()
        assert cfg.requests_per_second == 5.0
        assert cfg.per_domain is True
        assert cfg.adaptive is True
        assert cfg.min_rate == 0.5

    def test_adaptive_disabled(self):
        cfg = RateLimitConfig(adaptive=False)
        assert cfg.adaptive is False

    def test_requests_per_second_zero_rejected(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(requests_per_second=0.0)

    def test_min_rate_at_boundary(self):
        cfg = RateLimitConfig(min_rate=0.1)
        assert cfg.min_rate == 0.1

    def test_min_rate_below_boundary_rejected(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(min_rate=0.05)

    def test_latency_window_bounds(self):
        cfg = RateLimitConfig(latency_window=5)
        assert cfg.latency_window == 5
        cfg = RateLimitConfig(latency_window=50)
        assert cfg.latency_window == 50

    def test_latency_window_below_min_rejected(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(latency_window=4)


class TestProxyConfigProxyList:
    """Tests for ProxyConfig.proxy_list field and its validator."""

    def test_none_stays_none(self):
        """None proxy_list should remain None."""
        cfg = ProxyConfig(proxy_list=None)
        assert cfg.proxy_list is None

    def test_string_normalized_to_list(self):
        """Comma-separated string should be parsed into a list."""
        cfg = ProxyConfig(
            proxy_list="http://p1.example.com:8080, http://p2.example.com:8080"
        )
        assert isinstance(cfg.proxy_list, list)
        assert len(cfg.proxy_list) == 2
        assert "http://p1.example.com:8080" in cfg.proxy_list
        assert "http://p2.example.com:8080" in cfg.proxy_list

    def test_newline_separated_string(self):
        """Newline-separated string should be parsed into a list."""
        cfg = ProxyConfig(
            proxy_list="http://p1.example.com:8080\nhttp://p2.example.com:8080"
        )
        assert len(cfg.proxy_list) == 2

    def test_list_stays_as_list(self):
        """A list input should stay as a list."""
        proxies = ["http://p1.example.com:8080", "http://p2.example.com:8080"]
        cfg = ProxyConfig(proxy_list=proxies)
        assert cfg.proxy_list == proxies

    def test_empty_string_becomes_none(self):
        """Empty string should be normalized to None."""
        cfg = ProxyConfig(proxy_list="")
        assert cfg.proxy_list is None

    def test_empty_list_becomes_none(self):
        """Empty list (after filtering) should become None."""
        cfg = ProxyConfig(proxy_list=[])
        assert cfg.proxy_list is None

    def test_default_rotate_is_false(self):
        """Default rotate should be False."""
        cfg = ProxyConfig()
        assert cfg.rotate is False

    def test_default_rotation_interval(self):
        """Default rotation_interval should be 10."""
        cfg = ProxyConfig()
        assert cfg.rotation_interval == 10

    def test_rotation_interval_must_be_positive(self):
        """rotation_interval < 1 should be rejected by Pydantic."""
        with pytest.raises(ValidationError):
            ProxyConfig(rotation_interval=0)


# =============================================================================
# APIConfig CORS Tests
# =============================================================================


class TestAPIConfigCORS:
    """Tests for APIConfig CORS fields and validators."""

    def test_cors_defaults_are_secure(self):
        """Default CORS config should be secure by default."""
        cfg = APIConfig()
        assert cfg.cors_origins == []
        assert cfg.cors_allow_credentials is False
        assert cfg.cors_allow_methods == ["GET", "POST", "PUT", "DELETE", "PATCH"]
        assert cfg.cors_allow_headers == ["Authorization", "Content-Type", "X-API-Key"]
        assert cfg.cors_expose_headers == []

    def test_cors_origins_from_list(self):
        """CORS origins should accept a list."""
        cfg = APIConfig(cors_origins=["http://localhost:3000", "https://example.com"])
        assert cfg.cors_origins == ["http://localhost:3000", "https://example.com"]

    def test_cors_origins_from_string(self):
        """CORS origins should parse comma-separated string."""
        cfg = APIConfig(cors_origins="http://localhost:3000, https://example.com")
        assert cfg.cors_origins == ["http://localhost:3000", "https://example.com"]

    def test_cors_methods_from_list(self):
        """CORS methods should accept a list."""
        cfg = APIConfig(cors_allow_methods=["GET", "POST"])
        assert cfg.cors_allow_methods == ["GET", "POST"]

    def test_cors_methods_from_string(self):
        """CORS methods should parse comma-separated string."""
        cfg = APIConfig(cors_allow_methods="get, post, options")
        assert cfg.cors_allow_methods == ["GET", "POST", "OPTIONS"]

    def test_cors_headers_from_list(self):
        """CORS headers should accept a list."""
        cfg = APIConfig(cors_allow_headers=["Authorization"])
        assert cfg.cors_allow_headers == ["Authorization"]

    def test_cors_headers_from_string(self):
        """CORS headers should parse comma-separated string."""
        cfg = APIConfig(cors_allow_headers="Authorization, X-Custom")
        assert cfg.cors_allow_headers == ["Authorization", "X-Custom"]

    def test_cors_expose_headers_from_string(self):
        """CORS expose headers should parse comma-separated string."""
        cfg = APIConfig(cors_expose_headers="X-Total-Count, X-Page")
        assert cfg.cors_expose_headers == ["X-Total-Count", "X-Page"]

    def test_cors_credentials_true(self):
        """CORS credentials should be configurable."""
        cfg = APIConfig(cors_allow_credentials=True)
        assert cfg.cors_allow_credentials is True

    def test_cors_empty_origins_with_credentials(self):
        """Empty origins with credentials should be allowed (middleware handles it)."""
        cfg = APIConfig(cors_origins=[], cors_allow_credentials=True)
        assert cfg.cors_origins == []
        assert cfg.cors_allow_credentials is True


# =============================================================================
# api.trusted_proxies (client identification)
# =============================================================================


class TestAPIConfigTrustedProxies:
    """Proxy allow-list: default safe, explicit validation of entries."""

    def test_default_is_empty(self):
        """Empty list = X-Forwarded-For always ignored (secure default)."""
        assert APIConfig().trusted_proxies == []

    def test_accepts_ipv4_ipv6_and_cidr_entries(self):
        cfg = APIConfig(trusted_proxies=["127.0.0.1", "::1", "10.0.0.0/8"])
        assert cfg.trusted_proxies == ["127.0.0.1/32", "::1/128", "10.0.0.0/8"]

    def test_accepts_comma_separated_string(self):
        cfg = APIConfig(trusted_proxies="127.0.0.1, 10.0.0.0/8")
        assert cfg.trusted_proxies == ["127.0.0.1/32", "10.0.0.0/8"]

    def test_empty_entries_are_dropped(self):
        cfg = APIConfig(trusted_proxies=["", "  ", "10.0.0.1"])
        assert cfg.trusted_proxies == ["10.0.0.1/32"]

    def test_host_bits_are_masked_with_warning(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="ciberwebscan.config.models"):
            cfg = APIConfig(trusted_proxies=["10.0.0.1/8"])
        assert cfg.trusted_proxies == ["10.0.0.0/8"]
        assert any("host bits" in r.message for r in caplog.records)

    def test_ipv4_mapped_network_converted_to_ipv4(self):
        cfg = APIConfig(trusted_proxies=["::ffff:10.0.0.0/104"])
        assert cfg.trusted_proxies == ["10.0.0.0/8"]

    def test_invalid_entries_rejected(self):
        for bad in ["not-an-ip", "1.2.3.4/33", "999.999.999.999", "10.0.0.0/8x"]:
            with pytest.raises(ValidationError):
                APIConfig(trusted_proxies=[bad])

    def test_scalar_non_ip_value_rejected(self):
        with pytest.raises(ValidationError):
            APIConfig(trusted_proxies=10)

    def test_ipv4_mapped_prefix_below_96_rejected(self):
        """A mapped entry wider than /96 would over-match; reject loudly."""
        with pytest.raises(ValidationError):
            APIConfig(trusted_proxies=["::ffff:10.0.0.0/64"])

    def test_ipv4_mapped_prefix_96_rejected(self):
        """A mapped /96 covers every IPv4 peer; reject as catch-all."""
        with pytest.raises(ValidationError):
            APIConfig(trusted_proxies=["::ffff:10.0.0.0/96"])

    def test_catch_all_networks_rejected(self):
        """0.0.0.0/0 or ::/0 would trust every peer; reject loudly."""
        for bad in ["0.0.0.0/0", "::/0"]:
            with pytest.raises(ValidationError):
                APIConfig(trusted_proxies=[bad])

    def test_ipv6_zone_identifiers_rejected(self):
        """Zone IDs never appear on real peers; they over-match silently."""
        with pytest.raises(ValidationError):
            APIConfig(trusted_proxies=["fe80::1%eth0"])
