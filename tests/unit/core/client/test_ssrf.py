"""Unit tests for the SSRF policy module."""

from __future__ import annotations

import socket

import pytest

from ciberwebscan.core.client.ssrf import (
    SSRFBlockedError,
    check_url,
    clear_dns_cache,
    resolve_host,
)


class TestFormatValidation:
    """URL format checks (scheme, host, whitespace)."""

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "   ",
            "not-a-url",
            "://missing-scheme",
            "example.com",
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hi",
            "http://",
            "https://",
            "http://exa mple.com/",
        ],
    )
    def test_blocked_formats(self, url: str) -> None:
        with pytest.raises(SSRFBlockedError) as exc_info:
            check_url(url)
        assert "ssrf" in str(exc_info.value).lower()
        assert "blocked" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com",
            "http://example.com:8080/path?q=1",
            "https://user:pass@example.com/",
            "https://example.com/path%20with%20spaces",
            "https://example.com/путь",
        ],
    )
    def test_allowed_formats(self, url: str) -> None:
        check_url(url)  # Must not raise


class TestIpLiteralBlocking:
    """Non-canonical and private IPv4/IPv6 literals are blocked."""

    @pytest.mark.parametrize(
        "host",
        [
            # Loopback forms (canonical, shorthand, decimal, hex, octal)
            "127.0.0.1",
            "127.0.0.2",
            "127.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "0x7f.0x0.0x0.0x1",
            # Unspecified / broadcast-adjacent
            "0.0.0.0",
            # RFC1918
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
            # Link-local / cloud metadata
            "169.254.169.254",
            "169.254.0.1",
            # CGNAT (100.64.0.0/10)
            "100.64.0.1",
            # Multicast / reserved
            "224.0.0.1",
            "240.0.0.1",
            # TEST-NET (not globally routable)
            "192.0.2.1",
            # IPv6 loopback / link-local / unique-local / mapped / NAT64
            "[::1]",
            "[fe80::1]",
            "[fd00::1]",
            "[::ffff:127.0.0.1]",
            "[64:ff9b::7f00:1]",
            "[ff02::1]",
        ],
    )
    def test_private_literals_blocked(self, host: str) -> None:
        with pytest.raises(SSRFBlockedError) as exc_info:
            check_url(f"http://{host}/")
        assert "ssrf" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "host",
        ["8.8.8.8", "93.184.216.34", "[2606:4700:4700::1111]"],
    )
    def test_public_literals_allowed(self, host: str) -> None:
        check_url(f"https://{host}/")  # Must not raise


class TestHostnameResolutionBlocking:
    """Hostnames are resolved and classified before any request."""

    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "api.localhost",
            "localtest.me",  # DNS -> 127.0.0.1
            "127.0.0.1.nip.io",  # DNS -> 127.0.0.1
            "metadata.google.internal",  # DNS -> 169.254.169.254
        ],
    )
    def test_local_hostnames_blocked(self, host: str) -> None:
        with pytest.raises(SSRFBlockedError) as exc_info:
            check_url(f"http://{host}/")
        assert "ssrf" in str(exc_info.value).lower()

    def test_public_hostname_allowed(self) -> None:
        check_url("https://example.com/page")  # Must not raise

    def test_resolution_failure_fails_closed(self) -> None:
        """Unresolvable hosts are blocked, not allowed through."""
        with pytest.raises(SSRFBlockedError) as exc_info:
            check_url("http://nonexistent.invalid/")
        message = str(exc_info.value).lower()
        assert "ssrf" in message
        assert "could not be resolved" in message

    def test_resolve_host_raises_on_failure(self) -> None:
        with pytest.raises(socket.gaierror):
            resolve_host("nonexistent.invalid")

    def test_one_private_address_among_many_blocks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A single private A record in the answer set blocks the host."""

        def mixed_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ]

        clear_dns_cache()
        monkeypatch.setattr(socket, "getaddrinfo", mixed_getaddrinfo)
        with pytest.raises(SSRFBlockedError):
            check_url("http://mixed-answer.test/")

    def test_all_public_addresses_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def public_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            ]

        clear_dns_cache()
        monkeypatch.setattr(socket, "getaddrinfo", public_getaddrinfo)
        check_url("http://public-answer.test/")  # Must not raise


class TestAllowLocalOptIn:
    """allow_local=True skips classification and performs no DNS lookups."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localtest.me/",
        ],
    )
    def test_local_targets_allowed(self, url: str) -> None:
        check_url(url, allow_local=True)  # Must not raise

    def test_no_dns_lookups_when_allow_local(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(*args, **kwargs):
            raise AssertionError("DNS must not be queried when allow_local=True")

        monkeypatch.setattr(socket, "getaddrinfo", explode)
        check_url("http://localtest.me/", allow_local=True)

    def test_format_still_enforced_when_allow_local(self) -> None:
        with pytest.raises(SSRFBlockedError):
            check_url("file:///etc/passwd", allow_local=True)
        with pytest.raises(SSRFBlockedError):
            check_url("", allow_local=True)


class TestDnsCache:
    """Successful resolutions are cached with a TTL."""

    def test_repeat_resolution_uses_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        original = socket.getaddrinfo

        def counting(*args, **kwargs):
            calls.append(args[0])
            return original(*args, **kwargs)

        clear_dns_cache()
        monkeypatch.setattr(socket, "getaddrinfo", counting)

        assert resolve_host("example.com") == ["93.184.216.34"]
        assert resolve_host("example.com") == ["93.184.216.34"]
        assert calls.count("example.com") == 1

        clear_dns_cache()
        resolve_host("example.com")
        assert calls.count("example.com") == 2

    def test_clear_cache_between_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        original = socket.getaddrinfo

        def counting(*args, **kwargs):
            calls.append(args[0])
            return original(*args, **kwargs)

        clear_dns_cache()
        monkeypatch.setattr(socket, "getaddrinfo", counting)

        resolve_host("example.com")
        clear_dns_cache()
        resolve_host("example.com")
        assert len(calls) == 2
