"""Proxy-endpoint SSRF policy tests.

``check_proxy_url`` classifies the endpoint the client actually connects
to (the proxy), independently from the request-target policy in
``check_url``. Hostname answers come from the shared fake DNS resolver
fixture in ``tests/conftest.py``; no real resolution or connection ever
happens here.
"""

from __future__ import annotations

import pytest

from ciberwebscan.core.client.ssrf import (
    PROXY_ALLOWED_SCHEMES,
    SSRFBlockedError,
    check_proxy_url,
    check_url,
)

pytestmark = pytest.mark.unit

# Loopback/private/link-local/CGNAT plus non-canonical IPv4 notations:
# every one of these must be rejected before any socket is opened.
BLOCKED_BY_DEFAULT = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://localtest.me:8080",  # fake DNS -> 127.0.0.1
    "http://10.0.0.5:3128",
    "http://192.168.1.10:8080",
    "http://172.16.0.1:8080",
    "http://169.254.169.254",  # link-local / cloud IMDS
    "http://metadata.google.internal",  # fake DNS -> 169.254.169.254
    "http://100.64.0.1:8080",  # CGNAT shared address space
    "http://0.0.0.0:8080",  # unspecified / "this network"
    "http://[::1]:8080",
    "http://[fe80::1]:8080",
    "http://[fc00::1]:1080",  # IPv6 ULA
    "http://[::]:8080",  # unspecified IPv6
    "socks5://127.0.0.1:1080",
    "socks5://10.0.0.5:1080",
    "http://2130706433:8080",  # decimal loopback
    "http://0x7f000001:8080",  # hex loopback
    "http://127.1:8080",  # short-form loopback
    "http://0177.0.0.1:8080",  # octal loopback
    "http://[::ffff:127.0.0.1]:8080",  # IPv4-mapped loopback
    "http://[::ffff:169.254.169.254]:80",  # IPv4-mapped IMDS
]

# Accepted once the operator explicitly authorizes local proxies.
ALLOWED_WITH_LOCAL = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://192.168.1.10:8080",
    "http://10.0.0.5:3128",
    "http://172.16.0.1:3128",
    "http://[::1]:1080",
    "socks5://localhost:1080",
    "http://user:pass@192.168.1.10:8080",
]

# Infrastructure ranges: blocked even with local proxies authorized.
STILL_BLOCKED_WITH_LOCAL = [
    "http://169.254.169.254",  # IMDS
    "http://metadata.google.internal",  # DNS -> IMDS
    "http://100.64.0.1:8080",  # CGNAT
    "http://0.0.0.0:8080",  # unspecified
    "http://[fe80::1]:8080",  # IPv6 link-local
    "http://[::]:8080",  # unspecified IPv6
    "http://224.0.0.1:8080",  # multicast
    "http://240.0.0.1:8080",  # reserved
    "http://[::ffff:169.254.169.254]:80",  # IPv4-mapped IMDS
]

PUBLICLY_VALID = [
    "http://proxy.example.com:8080",
    "https://proxy.example.com:8443",
    "socks5://proxy.example.com:1080",
    "http://93.184.216.34:8080",
    "http://user:pass@proxy.example.com:3128",
]


class TestProxyBlockedByDefault:
    """Scenarios 1-6: local/private/metadata proxies are rejected."""

    @pytest.mark.parametrize("proxy", BLOCKED_BY_DEFAULT)
    def test_blocked_by_default(self, proxy: str) -> None:
        with pytest.raises(SSRFBlockedError) as exc:
            check_proxy_url(proxy)
        assert "ssrf" in str(exc.value).lower()
        assert "blocked" in str(exc.value).lower()

    def test_hostname_resolving_to_private_is_blocked(self) -> None:
        """Scenario 5: DNS name that resolves to a forbidden address."""
        with pytest.raises(SSRFBlockedError, match="localtest\\.me"):
            check_proxy_url("http://localtest.me:8080")

    def test_dns_failure_is_fail_closed(self) -> None:
        """Scenario 6: unresolvable proxy hosts are blocked, not allowed."""
        with pytest.raises(SSRFBlockedError, match="could not be resolved"):
            check_proxy_url("http://nonexistent.invalid:8080")


class TestProxyPubliclyValid:
    """Scenario 7: public proxies keep working."""

    @pytest.mark.parametrize("proxy", PUBLICLY_VALID)
    def test_public_proxy_accepted(self, proxy: str) -> None:
        check_proxy_url(proxy)  # must not raise

    def test_public_hostname_with_dns_is_accepted(self) -> None:
        check_proxy_url("http://public.example.com:8080")


class TestProxyCredentials:
    """Scenario 8: credentials are accepted but never echoed back."""

    def test_credentials_do_not_break_validation(self) -> None:
        check_proxy_url("http://user:pass@proxy.example.com:3128")

    def test_credentials_not_leaked_in_error(self) -> None:
        with pytest.raises(SSRFBlockedError) as exc:
            check_proxy_url("http://user:S3cr3t@127.0.0.1:8080")
        message = str(exc.value)
        assert "S3cr3t" not in message
        assert "user:" not in message


class TestProxySchemesAndFormat:
    """Scenario 9: only actually-supported schemes are accepted."""

    def test_allowed_schemes(self) -> None:
        assert frozenset({"http", "https", "socks5"}) == PROXY_ALLOWED_SCHEMES

    @pytest.mark.parametrize(
        "proxy",
        [
            "ftp://proxy.example.com:21",
            "file:///etc/passwd",
            "gopher://proxy.example.com:70",
            "ws://proxy.example.com:80",
        ],
    )
    def test_unsupported_scheme_blocked(self, proxy: str) -> None:
        with pytest.raises(SSRFBlockedError, match="unsupported scheme"):
            check_proxy_url(proxy)

    @pytest.mark.parametrize(
        "proxy",
        [
            "",
            "   ",
            "http://",
            "http://proxy.example.com:notaport",
            "http://proxy.example.com:99999",
        ],
    )
    def test_malformed_proxy_blocked(self, proxy: str) -> None:
        with pytest.raises(SSRFBlockedError):
            check_proxy_url(proxy)


class TestProxyLocalOptIn:
    """Scenario 10: explicit local proxies work, infrastructure stays blocked."""

    @pytest.mark.parametrize("proxy", ALLOWED_WITH_LOCAL)
    def test_local_proxy_allowed_when_opted_in(self, proxy: str) -> None:
        check_proxy_url(proxy, allow_local=True)  # must not raise

    @pytest.mark.parametrize("proxy", STILL_BLOCKED_WITH_LOCAL)
    def test_infrastructure_stays_blocked_with_opt_in(self, proxy: str) -> None:
        with pytest.raises(SSRFBlockedError):
            check_proxy_url(proxy, allow_local=True)


class TestTargetAndProxyAuthorizationsAreIndependent:
    """Scenario 18: neither allow_local opt-in authorizes the other."""

    def test_target_opt_in_does_not_permit_local_proxy(self) -> None:
        check_url("http://127.0.0.1/", allow_local=True)  # targets: allowed
        with pytest.raises(SSRFBlockedError):
            check_proxy_url("http://127.0.0.1:8080")  # proxies: still blocked

    def test_proxy_opt_in_does_not_permit_local_target(self) -> None:
        check_proxy_url("http://127.0.0.1:8080", allow_local=True)  # proxies ok
        with pytest.raises(SSRFBlockedError):
            check_url("http://127.0.0.1/")  # targets: still blocked

    def test_default_target_policy_unchanged(self) -> None:
        """BUG-004 behaviour is preserved for targets."""
        with pytest.raises(SSRFBlockedError):
            check_url("http://169.254.169.254/")
        with pytest.raises(SSRFBlockedError):
            check_url("http://2130706433/")
        check_url("http://public.example.com/")
