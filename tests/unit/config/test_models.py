"""
Unit tests for configuration models — proxy rotation fields, retry config,
and rate limit config.
"""

import pytest
from pydantic import ValidationError

from ciberwebscan.config.models import ProxyConfig, RateLimitConfig, RetryConfig


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
