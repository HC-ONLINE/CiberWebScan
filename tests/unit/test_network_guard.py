"""Regression tests for the unit-suite network barrier.

Guards against the PR #108 performance regression: accidental real TCP
connections from unmarked unit tests must fail instantly instead of
waiting for connect timeouts and HTTPClient retries on CI runners.
"""

from __future__ import annotations

import errno
import socket
import threading
import time

import pytest

from tests.network_guard import is_loopback_address

pytestmark = pytest.mark.unit


class TestIsLoopbackAddress:
    """Table tests for the address classifier."""

    @pytest.mark.parametrize(
        "address",
        [
            ("127.0.0.1", 80),
            ("127.0.0.1", 443),
            ("127.5.5.5", 8080),
            ("::1", 443),
            ("::ffff:127.0.0.1", 443),
            ("localhost", 80),
            ("LOCALHOST", 80),
            "/tmp/unix.sock",
        ],
    )
    def test_allowed(self, address):
        assert is_loopback_address(address) is True

    @pytest.mark.parametrize(
        "address",
        [
            ("93.184.216.34", 443),
            ("8.8.8.8", 53),
            ("169.254.169.254", 80),
            ("192.168.1.1", 80),
            ("10.0.0.1", 80),
            ("::ffff:8.8.8.8", 443),
            ("example.com", 443),
            ("metadata.google.internal", 80),
        ],
    )
    def test_blocked(self, address):
        assert is_loopback_address(address) is False


class TestConnectionBarrier:
    """The autouse conftest fixture must reject external TCP instantly."""

    def test_external_connect_raises_immediately(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        start = time.monotonic()
        try:
            with pytest.raises(ConnectionRefusedError) as excinfo:
                sock.connect(("93.184.216.34", 80))
        finally:
            sock.close()
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"blocked connect took {elapsed:.2f}s"
        assert excinfo.value.errno == errno.ECONNREFUSED

    def test_external_connect_ex_returns_econnrefused(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        start = time.monotonic()
        try:
            error = sock.connect_ex(("93.184.216.34", 80))
        finally:
            sock.close()
        elapsed = time.monotonic() - start
        assert error == errno.ECONNREFUSED
        assert elapsed < 1.0, f"blocked connect_ex took {elapsed:.2f}s"

    def test_loopback_connect_still_allowed(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        accepted: list[socket.socket] = []

        def accept():
            conn, _addr = listener.accept()
            accepted.append(conn)

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect(("127.0.0.1", port))
            thread.join(timeout=5)
            assert accepted, "loopback connection was not accepted"
        finally:
            client.close()
            listener.close()
            if accepted:
                accepted[0].close()
