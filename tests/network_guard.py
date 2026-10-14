"""Network-isolation helpers shared by conftest and the guard's own tests.

The unit-test suite must never open TCP connections to non-loopback
destinations: accidental real requests turn fast unit tests into
multi-minute waits on CI runners where external IPs blackhole instead of
refusing connections (the 15-minute regression introduced by the SSRF
fake-DNS fixture in PR #108).
"""

from __future__ import annotations

import ipaddress

# Names that RFC 6761 reserves for loopback; a resolver may legitimately
# hand these to connect() without a preceding getaddrinfo() call.
_LOOPBACK_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)


def is_loopback_address(address: object) -> bool:
    """Return True when a socket *address* targets loopback (or is not TCP).

    Args:
        address: The address passed to ``socket.socket.connect``. TCP
            addresses are ``(host, port)`` tuples (IPv6: 4 fields); other
            families (e.g. AF_UNIX paths) are passed through as allowed.

    Returns:
        True when the connection may proceed: AF_UNIX and other non-TCP
        addresses, loopback IPs (including IPv4-mapped IPv6) and the
        reserved loopback names. Unknown hostnames and any public or
        private non-loopback IP are rejected (fail-closed: private ranges
        are exactly what the SSRF policy must keep out of unit tests).
    """
    if not isinstance(address, tuple) or len(address) < 2:
        # AF_UNIX paths and other non-TCP address shapes: not our scope.
        return True

    host = address[0]
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    if not isinstance(host, str):
        return True
    if host.lower() in _LOOPBACK_NAMES:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname passed straight to connect(): we cannot prove it is
        # loopback, so refuse it. Resolvers hand connect() literal IPs.
        return False

    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_loopback)
