"""
Unit tests for configuration models — proxy rotation fields.
"""

import pytest
from pydantic import ValidationError

from ciberwebscan.config.models import ProxyConfig


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
