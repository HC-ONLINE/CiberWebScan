"""
SSRF protection policy.

Single source of truth for deciding whether a target URL may be requested
(:func:`check_url`) or a proxy endpoint may be connected to
(:func:`check_proxy_url`). Both validate scheme/format, resolve hostnames,
fold non-canonical IPv4 notations (``127.1``, ``2130706433``,
``0x7f000001``, ``0177.0.0.1``) and classify every resulting address
against the local/private/link-local/multicast/reserved ranges.

Used by :func:`ciberwebscan.core.scraping.helpers.is_safe_url`, by
:class:`~ciberwebscan.core.client.http_client.HTTPClient` (proxy check at
construction time plus a synchronous request event hook so every redirect
hop is re-validated before any bytes are sent), by the Playwright dynamic
scraper (browser context proxy and WebSocket routes) and by the service
layer.

The two authorizations are deliberately independent:

- ``allow_local`` on :func:`check_url` permits local/private *targets*.
- ``allow_local`` on :func:`check_proxy_url` permits local/private
  *proxies* (e.g. Burp Suite or mitmproxy on the operator workstation).

Neither grants the other, and proxy ``allow_local`` never permits
link-local/IMDS, multicast, reserved or CGNAT addresses.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from urllib.parse import ParseResult, SplitResult, urlparse, urlsplit

logger = logging.getLogger(__name__)

# How long successful resolutions are reused. Keeps per-request validation
# cheap during attack payloads and pagination loops.
DNS_TTL_SECONDS = 60.0

_dns_cache: dict[str, tuple[float, list[str]]] = {}
_dns_lock = threading.Lock()

# Schemes accepted for proxy endpoints. Only what httpx (via httpcore/
# socksio) and the Playwright browser context actually support.
PROXY_ALLOWED_SCHEMES = frozenset({"http", "https", "socks5"})

# Ranges that stay blocked even when local proxies are authorized
# (``check_proxy_url(allow_local=True)``): link-local — which includes the
# cloud instance metadata service —, CGNAT shared address space,
# multicast, reserved (incl. IPv4 broadcast) and unspecified addresses.
_ALWAYS_FORBIDDEN_NETWORKS: tuple[
    ipaddress.IPv4Network | ipaddress.IPv6Network, ...
] = (
    ipaddress.ip_network("0.0.0.0/8"),  # "this network" / unspecified
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT shared address space
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud IMDS
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved + broadcast
    ipaddress.ip_network("::/128"),  # unspecified
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
)


class SSRFBlockedError(Exception):
    """A URL was rejected by the SSRF policy.

    The message is user-facing; it always mentions ``SSRF`` and ``blocked``
    (and ``private`` for classification failures) so callers and tests can
    match on it.
    """


def clear_dns_cache() -> None:
    """Empty the DNS resolution cache (used by tests)."""
    with _dns_lock:
        _dns_cache.clear()


def resolve_host(host: str) -> list[str]:
    """Resolve *host* to a list of IP address strings (A and AAAA).

    Results are cached for :data:`DNS_TTL_SECONDS`.

    Args:
        host: Hostname or domain to resolve.

    Returns:
        Unique IP address strings in resolver order.

    Raises:
        socket.gaierror: If the name cannot be resolved. Callers of the
            policy treat resolution failures as blocks (fail-closed).
    """
    now = time.monotonic()
    with _dns_lock:
        cached = _dns_cache.get(host)
        if cached is not None and cached[0] > now:
            return list(cached[1])

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise socket.gaierror(f"Cannot resolve '{host}': {exc}") from exc

    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        # sockaddr[0] is always the address string; narrow it for type
        # checkers (IPv6 sockaddr tuples add more int fields).
        if isinstance(address, str) and address not in addresses:
            addresses.append(address)
    if not addresses:
        raise socket.gaierror(f"No addresses returned for '{host}'")

    with _dns_lock:
        _dns_cache[host] = (now + DNS_TTL_SECONDS, list(addresses))
    return addresses


def _parse_ip_literal(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the IP address *host* denotes, or None if *host* is a name."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    # Non-canonical IPv4 forms ("127.1", "2130706433", "0x7f000001",
    # "0177.0.0.1"): inet_aton folds them exactly the way common platform
    # resolvers do, while plain names raise OSError.
    try:
        return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(host)))
    except OSError:
        return None


def _address_is_forbidden(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_local: bool = False,
) -> bool:
    """Return True when *ip* must not be contacted under the policy.

    Args:
        ip: Address to classify (IPv4-mapped IPv6 is unwrapped first).
        allow_local: Permit loopback, RFC1918/ULA and globally routable
            addresses. Infrastructure-sensitive ranges (link-local/cloud
            IMDS, CGNAT, multicast, reserved, unspecified) stay blocked
            even when this is True. Mirrors ``ipaddress`` semantics
            explicitly so the result does not drift across Python
            versions (``is_private`` widened in 3.13).
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped

    if allow_local:
        return any(
            ip.version == network.version and ip in network
            for network in _ALWAYS_FORBIDDEN_NETWORKS
        )

    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or not ip.is_global
    )


def _check_host(host: str, *, allow_local: bool = False) -> None:
    """Raise :class:`SSRFBlockedError` if *host* resolves to a forbidden target.

    Args:
        host: Hostname or IP literal to classify.
        allow_local: Permit loopback/private addresses (see
            :func:`_address_is_forbidden`). ``localhost`` names are then
            treated as loopback without a DNS lookup (RFC 6761).
    """
    if host == "localhost" or host.endswith(".localhost"):
        # RFC 6761 reserves these names for loopback; no DNS needed.
        if allow_local:
            return
        raise SSRFBlockedError(
            f"SSRF protection: host '{host}' is a local loopback name "
            "and is blocked by default."
        )

    literal = _parse_ip_literal(host)
    if literal is not None:
        if _address_is_forbidden(literal, allow_local=allow_local):
            raise SSRFBlockedError(
                f"SSRF protection: target '{host}' points to a local or "
                f"private network address ({literal}) and is blocked by default."
            )
        return

    try:
        addresses = resolve_host(host)
    except Exception as exc:
        raise SSRFBlockedError(
            f"SSRF protection: host '{host}' could not be resolved ({exc}) "
            "and is blocked by default."
        ) from exc

    for address in addresses:
        try:
            resolved = ipaddress.ip_address(address)
        except ValueError:
            raise SSRFBlockedError(
                f"SSRF protection: host '{host}' resolved to an invalid "
                f"address ('{address}') and is blocked by default."
            ) from None
        if _address_is_forbidden(resolved, allow_local=allow_local):
            raise SSRFBlockedError(
                f"SSRF protection: host '{host}' resolves to a local or "
                f"private network address ({address}) and is blocked by default."
            )


def check_url(url: str, *, allow_local: bool = False) -> None:
    """Validate that *url* may be requested under the SSRF policy.

    Args:
        url: Absolute http(s) URL to validate.
        allow_local: Skip network classification entirely (format check
            only). Matches the documented ``allow_local`` opt-ins, which
            permit localhost, private and link-local targets and never
            perform DNS lookups.

    Raises:
        SSRFBlockedError: If the URL is malformed, uses a non-http(s)
            scheme, has no host, or its target is forbidden. Hostname
            resolution failures are treated as blocks (fail-closed).
    """
    if not url or any(char.isspace() for char in url):
        raise SSRFBlockedError(
            f"SSRF protection: URL '{url}' is malformed and is blocked by default."
        )

    try:
        parsed = urlparse(url)
    except ValueError:
        raise SSRFBlockedError(
            f"SSRF protection: URL '{url}' is malformed and is blocked by default."
        ) from None

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SSRFBlockedError(
            f"SSRF protection: URL '{url}' must be an absolute http(s) URL "
            "with a host; it is blocked by default."
        )

    if allow_local:
        return

    _check_host(parsed.hostname.lower())


def _display_proxy(parsed: SplitResult | ParseResult) -> str:
    """Return *parsed* proxy as ``scheme://host[:port]`` for user-facing
    messages, never including credentials."""
    host = parsed.hostname or ""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    port = ""
    try:
        if parsed.port is not None:
            port = f":{parsed.port}"
    except ValueError:
        port = ":<invalid>"
    return f"{parsed.scheme}://{host}{port}"


def check_proxy_url(proxy: str, *, allow_local: bool = False) -> None:
    """Validate that *proxy* may be connected to under the SSRF policy.

    The proxy endpoint is where the TCP connection is actually opened, so
    it must be classified independently of the request target. Callers
    (``HTTPClient``, the Playwright dynamic scraper, config ingestion)
    invoke this before any transport is created.

    Args:
        proxy: Proxy URL (``http://``, ``https://`` or ``socks5://``),
            optionally with ``user:pass@`` credentials. Credentials are
            accepted but never echoed back in error messages.
        allow_local: Permit loopback and RFC1918/ULA proxy endpoints
            (e.g. Burp Suite on the operator workstation). Independent
            from the ``allow_local`` target opt-in: neither authorizes the
            other. Link-local/IMDS, CGNAT, multicast, reserved and
            unspecified addresses stay blocked even when True.

    Raises:
        SSRFBlockedError: If the URL is malformed, uses an unsupported
            scheme, has no host or an invalid port, or its endpoint is
            forbidden. Hostname resolution failures are treated as blocks
            (fail-closed). Messages mention ``SSRF`` and ``blocked`` so
            callers and tests can match on them.
    """
    if not proxy or any(char.isspace() for char in proxy):
        raise SSRFBlockedError(
            "SSRF protection: proxy URL is malformed and is blocked by default."
        )

    try:
        parsed = urlsplit(proxy)
        host = parsed.hostname
        _ = parsed.port  # validates the port syntax
    except ValueError:
        raise SSRFBlockedError(
            "SSRF protection: proxy URL is malformed and is blocked by default."
        ) from None

    if parsed.scheme.lower() not in PROXY_ALLOWED_SCHEMES:
        allowed = ", ".join(sorted(PROXY_ALLOWED_SCHEMES))
        raise SSRFBlockedError(
            f"SSRF protection: proxy '{_display_proxy(parsed)}' uses an "
            f"unsupported scheme (allowed: {allowed}) and is blocked by default."
        )

    if not host:
        raise SSRFBlockedError(
            f"SSRF protection: proxy '{_display_proxy(parsed)}' has no host "
            "and is blocked by default."
        )

    _check_host(host.lower(), allow_local=allow_local)
