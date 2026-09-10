"""Integration tests for HTTPClient lifecycle with real HTTP connections.

Tests that HTTPClient properly manages connections using context managers
and explicit close() calls.
"""

from __future__ import annotations

import threading

from ciberwebscan.core.client.http_client import HTTPClient

HTTPBIN_URL = "https://httpbin.org"


class TestHTTPClientContextManager:
    """Test HTTPClient context manager with real HTTP requests."""

    def test_context_manager_makes_request(self):
        """Context manager should allow making requests."""
        with HTTPClient(timeout=10) as client:
            response = client.get(f"{HTTPBIN_URL}/get")
            assert response.status_code == 200

    def test_context_manager_closes_connection(self):
        """Context manager should close connection on exit."""
        with HTTPClient(timeout=10) as client:
            response = client.get(f"{HTTPBIN_URL}/get")
            assert response.status_code == 200

        # After context exit, client should be closed
        assert client._client.is_closed

    def test_multiple_sequential_clients(self):
        """Multiple sequential clients should not leak connections."""
        for _ in range(3):
            with HTTPClient(timeout=10) as client:
                response = client.get(f"{HTTPBIN_URL}/get")
                assert response.status_code == 200
                assert not client._client.is_closed

            # After context exit, client should be closed
            assert client._client.is_closed


class TestHTTPClientExplicitClose:
    """Test HTTPClient explicit close() with real HTTP requests."""

    def test_explicit_close_after_request(self):
        """Explicit close() should release resources after request."""
        client = HTTPClient(timeout=10)
        try:
            response = client.get(f"{HTTPBIN_URL}/get")
            assert response.status_code == 200
            assert not client._client.is_closed
        finally:
            client.close()

        assert client._client.is_closed

    def test_explicit_close_multiple_clients(self):
        """Multiple clients with explicit close should not leak."""
        clients = []
        try:
            for _ in range(3):
                client = HTTPClient(timeout=10)
                response = client.get(f"{HTTPBIN_URL}/get")
                assert response.status_code == 200
                clients.append(client)
        finally:
            for c in clients:
                c.close()

        for c in clients:
            assert c._client.is_closed


class TestHTTPClientExceptionSafety:
    """Test that HTTPClient cleans up on exceptions."""

    def test_context_manager_closes_on_exception(self):
        """Context manager should close even if exception occurs."""
        try:
            with HTTPClient(timeout=10) as client:
                raise ValueError("test exception")
        except ValueError:
            pass

        assert client._client.is_closed

    def test_explicit_close_on_exception(self):
        """Explicit close should work even after exception."""
        client = HTTPClient(timeout=10)
        try:
            raise ValueError("test exception")
        except ValueError:
            pass
        finally:
            client.close()

        assert client._client.is_closed


class TestHTTPClientConcurrent:
    """Test HTTPClient lifecycle with concurrent requests."""

    def test_concurrent_clients_close_properly(self):
        """Multiple concurrent clients should all close properly."""
        clients = []
        errors = []

        def make_request():
            try:
                client = HTTPClient(timeout=10)
                response = client.get(f"{HTTPBIN_URL}/get")
                if response.status_code != 200:
                    errors.append(f"Status {response.status_code}")
                clients.append(client)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=make_request) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors: {errors}"

        try:
            for client in clients:
                assert not client._client.is_closed
        finally:
            for client in clients:
                client.close()

        for client in clients:
            assert client._client.is_closed
