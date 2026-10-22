"""Real SOCKS5 transport verification.

A minimal local SOCKS5 relay plus a local HTTP origin prove that httpx
(with ``socksio`` from ``httpx[socks]``) really tunnels through a
``socks5://`` proxy — not just that the URL validates — and that the
SSRF policy still rejects the same endpoint without the local opt-in,
before any connection is attempted.
"""

from __future__ import annotations

import contextlib
import socket
import socketserver
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ciberwebscan.core.client import HTTPClient
from ciberwebscan.core.client.ssrf import SSRFBlockedError

pytestmark = [pytest.mark.network, pytest.mark.integration]


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly *size* bytes (loopback may deliver partial reads)."""
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


class _Socks5Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _Socks5Handler(socketserver.BaseRequestHandler):
    """Minimal SOCKS5 CONNECT relay (no auth; IPv4/IPv6/domain targets)."""

    def handle(self) -> None:
        sock: socket.socket = self.request
        header = _recv_exact(sock, 2)
        if len(header) < 2 or header[0] != 5:
            return
        methods = _recv_exact(sock, header[1])
        if b"\x00" not in methods:
            sock.sendall(b"\x05\xff")  # no acceptable auth method
            return
        sock.sendall(b"\x05\x00")  # no authentication required

        request = _recv_exact(sock, 4)
        if len(request) < 4 or request[0] != 5 or request[1] != 1:
            return
        atyp = request[3]
        if atyp == 1:  # IPv4
            host = socket.inet_ntoa(_recv_exact(sock, 4))
        elif atyp == 3:  # domain name
            length = _recv_exact(sock, 1)[0]
            host = _recv_exact(sock, length).decode()
        elif atyp == 4:  # IPv6
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
        else:
            return
        port = int.from_bytes(_recv_exact(sock, 2), "big")

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            sock.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)  # general failure
            return

        sock.sendall(
            b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + (0).to_bytes(2, "big")
        )

        def _pump(source: socket.socket, destination: socket.socket) -> None:
            try:
                while True:
                    chunk = source.recv(65536)
                    if not chunk:
                        break
                    destination.sendall(chunk)
            except OSError:
                pass
            finally:
                for side in (source, destination):
                    with contextlib.suppress(OSError):
                        side.shutdown(socket.SHUT_RDWR)

        pumps = [
            threading.Thread(target=_pump, args=(sock, upstream), daemon=True),
            threading.Thread(target=_pump, args=(upstream, sock), daemon=True),
        ]
        for pump in pumps:
            pump.start()
        for pump in pumps:
            pump.join(timeout=10)


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — http.server naming
        body = b"socks5-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence per-request logging."""


@pytest.fixture
def socks5_and_origin() -> Iterator[tuple[int, int]]:
    """Start a local SOCKS5 relay and HTTP origin on loopback."""
    origin = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    socks = _Socks5Server(("127.0.0.1", 0), _Socks5Handler)
    for server in (origin, socks):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield socks.server_address[1], origin.server_address[1]
    finally:
        for server in (origin, socks):
            server.shutdown()
            server.server_close()


class TestSocks5Transport:
    """Scenario 12/9 (P4): SOCKS5 works for real or is rejected explicitly."""

    def test_real_socks5_tunnel(self, socks5_and_origin: tuple[int, int]) -> None:
        proxy_port, origin_port = socks5_and_origin

        with HTTPClient(
            proxy=f"socks5://127.0.0.1:{proxy_port}",
            allow_local_proxy=True,
            timeout=10.0,
        ) as client:
            response = client.get(f"http://127.0.0.1:{origin_port}/")

        assert response.status_code == 200
        assert response.text == "socks5-ok"

    def test_socks5_proxy_rejected_without_opt_in(
        self, socks5_and_origin: tuple[int, int]
    ) -> None:
        proxy_port, _origin_port = socks5_and_origin

        with pytest.raises(SSRFBlockedError):
            HTTPClient(proxy=f"socks5://127.0.0.1:{proxy_port}")
