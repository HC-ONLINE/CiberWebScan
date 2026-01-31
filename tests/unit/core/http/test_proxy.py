"""
Unit tests for proxy utilities.
"""

import pytest

from ciberwebscan.core.http import (
    ProxyRotator,
    ProxyValidationError,
    parse_proxy,
    parse_proxy_list,
    sanitize_proxy_for_display,
)


class TestParseProxy:
    """Tests for parse_proxy function."""

    def test_empty_string_returns_none(self):
        """Empty string should return None."""
        assert parse_proxy("") is None
        assert parse_proxy("   ") is None

    def test_valid_http_proxy(self):
        """Valid HTTP proxy should be parsed."""
        result = parse_proxy("http://proxy.com:8080")
        assert result == "http://proxy.com:8080"

    def test_valid_https_proxy(self):
        """Valid HTTPS proxy should be parsed."""
        result = parse_proxy("https://proxy.com:443")
        assert result == "https://proxy.com:443"

    def test_valid_socks5_proxy(self):
        """Valid SOCKS5 proxy should be parsed."""
        result = parse_proxy("socks5://proxy.com:1080")
        assert result == "socks5://proxy.com:1080"

    def test_proxy_with_credentials(self):
        """Proxy with user:pass should be parsed."""
        result = parse_proxy("http://user:pass@proxy.com:8080")
        assert result == "http://user:pass@proxy.com:8080"

    def test_adds_default_scheme(self):
        """Missing scheme should default to http://."""
        result = parse_proxy("proxy.com:8080")
        assert result == "http://proxy.com:8080"

    def test_invalid_format_raises(self):
        """Invalid format should raise ProxyValidationError."""
        # Note: parse_proxy adds http:// prefix, so we test truly invalid formats
        with pytest.raises(ProxyValidationError) as exc:
            parse_proxy("://invalid")
        assert "Invalid proxy format" in str(exc.value)

    def test_local_proxy_blocked_by_default(self):
        """Local proxies should be blocked by default."""
        with pytest.raises(ProxyValidationError) as exc:
            parse_proxy("http://localhost:8080")
        assert "Local proxies are not allowed" in str(exc.value)

        with pytest.raises(ProxyValidationError):
            parse_proxy("http://127.0.0.1:8080")

    def test_local_proxy_allowed_when_enabled(self):
        """Local proxies should work when allow_local=True and allow_private=True."""
        # localhost is both local and private, so need both flags
        result = parse_proxy("http://localhost:8080", allow_local=True, allow_private=True)
        assert result == "http://localhost:8080"

        result = parse_proxy("http://127.0.0.1:8080", allow_local=True, allow_private=True)
        assert result == "http://127.0.0.1:8080"

    def test_private_ip_blocked_by_default(self):
        """Private IP proxies should be blocked by default."""
        with pytest.raises(ProxyValidationError) as exc:
            parse_proxy("http://192.168.1.1:8080")
        assert "Private network proxies are not allowed" in str(exc.value)

        with pytest.raises(ProxyValidationError):
            parse_proxy("http://10.0.0.1:8080")

    def test_private_ip_allowed_when_enabled(self):
        """Private IP proxies should work when allow_private=True."""
        result = parse_proxy("http://192.168.1.1:8080", allow_private=True)
        assert result == "http://192.168.1.1:8080"

    def test_strips_whitespace(self):
        """Whitespace should be stripped."""
        result = parse_proxy("  http://proxy.com:8080  ")
        assert result == "http://proxy.com:8080"


class TestParseProxyList:
    """Tests for parse_proxy_list function."""

    def test_empty_returns_empty_list(self):
        """Empty string returns empty list."""
        assert parse_proxy_list("") == []
        assert parse_proxy_list(None) == []

    def test_comma_separated(self):
        """Comma-separated proxies should be parsed."""
        result = parse_proxy_list("http://p1:8080, http://p2:8080")
        assert result == ["http://p1:8080", "http://p2:8080"]

    def test_newline_separated(self):
        """Newline-separated proxies should be parsed."""
        result = parse_proxy_list("http://p1:8080\nhttp://p2:8080")
        assert result == ["http://p1:8080", "http://p2:8080"]

    def test_space_separated(self):
        """Space-separated proxies should be parsed."""
        result = parse_proxy_list("http://p1:8080 http://p2:8080")
        assert result == ["http://p1:8080", "http://p2:8080"]

    def test_mixed_separators(self):
        """Mixed separators should work."""
        result = parse_proxy_list("http://p1:8080, http://p2:8080\nhttp://p3:8080")
        assert len(result) == 3

    def test_invalid_proxy_raises(self):
        """Invalid proxy in list should raise."""
        # Use truly invalid format that can't be fixed with http:// prefix
        with pytest.raises(ProxyValidationError):
            parse_proxy_list("http://p1:8080, ://invalid, http://p2:8080")


class TestSanitizeProxyForDisplay:
    """Tests for sanitize_proxy_for_display function."""

    def test_empty_returns_empty(self):
        """Empty string returns empty."""
        assert sanitize_proxy_for_display("") == ""
        assert sanitize_proxy_for_display(None) == ""

    def test_removes_credentials(self):
        """Credentials should be removed."""
        result = sanitize_proxy_for_display("http://user:pass@proxy.com:8080")
        assert result == "proxy.com:8080"
        assert "user" not in result
        assert "pass" not in result

    def test_removes_scheme(self):
        """Scheme should be removed."""
        result = sanitize_proxy_for_display("http://proxy.com:8080")
        assert result == "proxy.com:8080"

        result = sanitize_proxy_for_display("socks5://proxy.com:1080")
        assert result == "proxy.com:1080"

    def test_no_credentials_just_removes_scheme(self):
        """Without credentials, just remove scheme."""
        result = sanitize_proxy_for_display("https://proxy.com:443")
        assert result == "proxy.com:443"


class TestProxyRotator:
    """Tests for ProxyRotator class."""

    def test_empty_list_raises(self):
        """Empty proxy list should raise ValueError."""
        with pytest.raises(ValueError) as exc:
            ProxyRotator([])
        assert "empty" in str(exc.value).lower()

    def test_single_proxy_rotation(self):
        """Single proxy should always return same value."""
        rotator = ProxyRotator(["http://proxy:8080"])
        assert rotator.next() == "http://proxy:8080"
        assert rotator.next() == "http://proxy:8080"

    def test_round_robin_rotation(self, sample_proxies):
        """Proxies should rotate in round-robin order."""
        rotator = ProxyRotator(sample_proxies)

        assert rotator.next() == sample_proxies[0]
        assert rotator.next() == sample_proxies[1]
        assert rotator.next() == sample_proxies[2]
        # Wrap around
        assert rotator.next() == sample_proxies[0]

    def test_current_does_not_advance(self, sample_proxies):
        """current() should not advance the index."""
        rotator = ProxyRotator(sample_proxies)

        assert rotator.current() == sample_proxies[0]
        assert rotator.current() == sample_proxies[0]
        rotator.next()
        assert rotator.current() == sample_proxies[1]

    def test_reset(self, sample_proxies):
        """reset() should return to first proxy."""
        rotator = ProxyRotator(sample_proxies)

        rotator.next()
        rotator.next()
        rotator.reset()

        assert rotator.current() == sample_proxies[0]

    def test_len(self, sample_proxies):
        """len() should return number of proxies."""
        rotator = ProxyRotator(sample_proxies)
        assert len(rotator) == len(sample_proxies)

    def test_iter(self, sample_proxies):
        """Should be iterable."""
        rotator = ProxyRotator(sample_proxies)
        assert list(rotator) == sample_proxies

    def test_add_proxy(self, sample_proxies):
        """add() should add new proxy."""
        rotator = ProxyRotator(sample_proxies.copy())
        new_proxy = "http://newproxy:8080"

        rotator.add(new_proxy)

        assert new_proxy in rotator.proxies
        assert len(rotator) == len(sample_proxies) + 1

    def test_add_duplicate_ignored(self, sample_proxies):
        """Adding duplicate proxy should be ignored."""
        rotator = ProxyRotator(sample_proxies.copy())
        initial_len = len(rotator)

        rotator.add(sample_proxies[0])

        assert len(rotator) == initial_len

    def test_remove_proxy(self, sample_proxies):
        """remove() should remove proxy."""
        rotator = ProxyRotator(sample_proxies.copy())
        to_remove = sample_proxies[1]

        result = rotator.remove(to_remove)

        assert result is True
        assert to_remove not in rotator.proxies
        assert len(rotator) == len(sample_proxies) - 1

    def test_remove_nonexistent_returns_false(self, sample_proxies):
        """Removing nonexistent proxy returns False."""
        rotator = ProxyRotator(sample_proxies.copy())

        result = rotator.remove("http://nonexistent:8080")

        assert result is False
        assert len(rotator) == len(sample_proxies)

    def test_remove_last_proxy_raises(self):
        """Removing last proxy should raise ValueError."""
        rotator = ProxyRotator(["http://only:8080"])

        with pytest.raises(ValueError) as exc:
            rotator.remove("http://only:8080")
        assert "last proxy" in str(exc.value).lower()

    def test_remove_adjusts_index(self):
        """Removing proxy before current index should adjust index."""
        rotator = ProxyRotator(["http://p1:8080", "http://p2:8080", "http://p3:8080"])

        # Advance to p2
        rotator.next()
        assert rotator.current() == "http://p2:8080"

        # Remove p1 (before current)
        rotator.remove("http://p1:8080")

        # Index should be adjusted, current should still be p2
        assert rotator.current() == "http://p2:8080"
