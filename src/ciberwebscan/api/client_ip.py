"""
Shared client IP resolution for the API layer.

Client identity comes from the connection peer (``request.client``).
``X-Forwarded-For`` is only consulted when the peer belongs to the declared
``api.trusted_proxies`` list, in which case the forwarded chain is walked from
right to left until the first address that a trusted proxy did not vouch for.
With no trusted proxies configured (the default) the header is always ignored.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable

from fastapi import Request

from ciberwebscan.config.loader import get_config

logger = logging.getLogger(__name__)

_UNKNOWN_CLIENT = "unknown"

_IPv4Address = ipaddress.IPv4Address
_IPv6Address = ipaddress.IPv6Address
_IPv4Network = ipaddress.IPv4Network
_IPv6Network = ipaddress.IPv6Network

_ClientAddress = _IPv4Address | _IPv6Address
_ClientNetwork = _IPv4Network | _IPv6Network


def _unwrap_mapped(address: _ClientAddress) -> _ClientAddress:
    """Return the IPv4 form of an IPv4-mapped IPv6 address (else itself)."""
    if isinstance(address, _IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _parse_ip(value: str) -> _ClientAddress | None:
    """Parse a single hop, or return None when it is not a valid IP."""
    try:
        return _unwrap_mapped(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _trusted_networks() -> list[_ClientNetwork]:
    """Parse ``api.trusted_proxies`` for this request (fail closed)."""
    try:
        entries = get_config().api.trusted_proxies
    except Exception:
        # Any unexpected config failure must not turn into a 500 or an
        # open header: empty list = X-Forwarded-For stays ignored.
        logger.warning(
            "Could not load api.trusted_proxies; ignoring X-Forwarded-For",
            exc_info=True,
        )
        return []
    networks: list[_ClientNetwork] = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(str(entry), strict=False))
        except ValueError:
            logger.warning("Ignoring invalid api.trusted_proxies entry: %r", entry)
    return networks


def _forwarded_for(request: Request) -> str:
    """Join all X-Forwarded-For header lines (Starlette semantics)."""
    headers = request.headers
    # Starlette's Headers exposes getlist(); mapping-style test doubles
    # may only provide get().
    getlist: Callable[[str], list[str]] | None = getattr(headers, "getlist", None)
    if getlist is not None:
        return ", ".join(getlist("x-forwarded-for"))
    value = headers.get("X-Forwarded-For", "")
    return value if isinstance(value, str) else ""


def resolve_client_ip(request: Request) -> str:
    """
    Resolve the client identity for rate limiting and log attribution.

    Args:
        request: The incoming request.

    Returns:
        The client IP as a string. The connection peer wins whenever
        ``X-Forwarded-For`` cannot be trusted: empty ``api.trusted_proxies``
        (default), peer outside that list, or peer not parseable as an IP
        (in which case the shared ``"unknown"`` bucket is used rather than
        echoing a non-IP peer string). Behind trusted proxies the chain is
        validated hop by hop from right to left and a malformed entry stops
        the walk (last trusted hop wins).
    """
    peer = request.client.host if request.client else None
    peer_ip = _parse_ip(peer) if isinstance(peer, str) and peer else None
    if peer_ip is None:
        # No usable peer (unix socket, test client, missing scope): never
        # consult a client-controlled header for identity, and never echo
        # an arbitrary peer string (it could be client-controlled under a
        # misconfigured upstream proxy).
        return _UNKNOWN_CLIENT

    forwarded = _forwarded_for(request)
    if not forwarded.strip():
        return str(peer_ip)

    trusted = _trusted_networks()
    if not trusted:
        logger.debug(
            "Ignoring X-Forwarded-For: no trusted proxies configured (%s)", peer_ip
        )
        return str(peer_ip)
    if not any(peer_ip in network for network in trusted):
        logger.debug(
            "Ignoring X-Forwarded-For: peer %s is not a trusted proxy", peer_ip
        )
        return str(peer_ip)

    # Peer is a declared proxy: walk the chain right to left (appended hops
    # are written by our proxies; the client controls only the left end).
    result = str(peer_ip)
    for entry in reversed(forwarded.split(",")):
        entry = entry.strip()
        if not entry:
            break
        hop = _parse_ip(entry)
        if hop is None:
            # Malformed hop: stop before touching client-controlled data.
            break
        if not any(hop in network for network in trusted):
            return str(hop)
        result = str(hop)
    return result
