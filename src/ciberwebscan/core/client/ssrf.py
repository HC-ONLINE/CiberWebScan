"""
SSRF protection policy.

Single source of truth for deciding whether a target URL may be requested.
Validates scheme/format, resolves hostnames, folds non-canonical IPv4
notations (``127.1``, ``2130706433``, ``0x7f000001``, ``0177.0.0.1``) and
classifies every resulting address against the local/private/link-local/
multicast/reserved ranges.

Used by :func:`ciberwebscan.core.scraping.helpers.is_safe_url`, by
:class:`~ciberwebscan.core.client.http_client.HTTPClient` through a
synchronous request event hook (so every redirect hop is re-validated
before any bytes are sent) and by the service layer.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# How long successful resolutions are reused. Keeps per-request validation
# cheap during attack payloads and pagination loops.
DNS_TTL_SECONDS = 60.0

_dns_cache: dict[str, tuple[float, list[str]]] = {}
_dns_lock = threading.Lock()


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


def _address_is_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True when *ip* must not be contacted under the policy."""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or not ip.is_global
    )


def _check_host(host: str) -> None:
    """Raise :class:`SSRFBlockedError` if *host* resolves to a forbidden target."""
    if host == "localhost" or host.endswith(".localhost"):
        # RFC 6761 reserves these names for loopback; no DNS needed.
        raise SSRFBlockedError(
            f"SSRF protection: host '{host}' is a local loopback name "
            "and is blocked by default."
        )

    literal = _parse_ip_literal(host)
    if literal is not None:
        if _address_is_forbidden(literal):
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
        if _address_is_forbidden(resolved):
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
