"""
Unit tests for the shared TLS context cache in HTTPClient (BUG-013).

Building httpx's default verification context re-reads the whole CA bundle
on every client construction (hundreds of milliseconds). HTTPClient now
reuses one process-wide ``ssl.SSLContext`` per shape. These tests pin the
cache behaviour and its isolation rules (http2/ALPN, trust_env, SSL_CERT_*).
"""

from __future__ import annotations

import ssl
from collections.abc import Iterator

import certifi
import pytest

from ciberwebscan.core.client.http_client import (
    HTTPClient,
    _shared_ssl_context,
    _ssl_context_cache,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def clear_ssl_cache() -> Iterator[None]:
    _ssl_context_cache.clear()
    yield
    _ssl_context_cache.clear()


@pytest.fixture
def create_context_calls(monkeypatch) -> list:
    """Record calls to ssl.create_default_context, passing through to it."""
    calls: list = []
    real_create = ssl.create_default_context

    def counting_create(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return real_create(*args, **kwargs)

    monkeypatch.setattr(ssl, "create_default_context", counting_create)
    return calls


class TestSharedSslContext:
    """Cache semantics of _shared_ssl_context."""

    def test_same_shape_reuses_one_context(self, create_context_calls: list):
        first = _shared_ssl_context(http2=True, trust_env=False)
        second = _shared_ssl_context(http2=True, trust_env=False)

        assert first is not None
        assert first is second
        assert len(create_context_calls) == 1, (
            "the CA bundle must be loaded once per shape, not per client"
        )
        assert create_context_calls[0]["kwargs"].get("cafile") == certifi.where()

    def test_http2_shapes_get_separate_contexts(self, create_context_calls: list):
        """httpcore sets ALPN on the shared context per connection, so
        HTTP/2 and HTTP/1.1-only clients must not share a context."""
        http2_ctx = _shared_ssl_context(http2=True, trust_env=False)
        http1_ctx = _shared_ssl_context(http2=False, trust_env=False)

        assert http2_ctx is not None and http1_ctx is not None
        assert http2_ctx is not http1_ctx
        assert len(create_context_calls) == 2

    def test_env_certs_ignored_without_trust_env(
        self, create_context_calls: list, monkeypatch
    ):
        """SSL_CERT_FILE only matters under trust_env (httpx parity)."""
        monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/cert.pem")

        context = _shared_ssl_context(http2=True, trust_env=False)

        assert context is not None
        # Built from the certifi bundle, not from the env var.
        assert create_context_calls[0]["kwargs"].get("cafile") == certifi.where()
        assert (True, None, None) in _ssl_context_cache
        assert (True, "/nonexistent/cert.pem", None) not in _ssl_context_cache

    def test_env_certs_honoured_under_trust_env(
        self, create_context_calls: list, monkeypatch
    ):
        """Under trust_env the cache key includes the resolved env value."""

        real_bundle = str(certifi.where())
        monkeypatch.setenv("SSL_CERT_FILE", real_bundle)

        context = _shared_ssl_context(http2=True, trust_env=True)

        assert context is not None
        assert create_context_calls[0]["kwargs"].get("cafile") == real_bundle
        assert (True, real_bundle, None) in _ssl_context_cache


class TestHTTPClientUsesSharedContext:
    """HTTPClient construction goes through the cache."""

    def test_verify_true_builds_context_once(self, create_context_calls: list):
        with HTTPClient(verify=True) as first, HTTPClient(verify=True) as second:
            assert first is not second
            assert len(create_context_calls) == 1, (
                "second client must reuse the cached TLS context"
            )

    def test_verify_false_does_not_build_context(self, create_context_calls: list):
        with HTTPClient(verify=False):
            assert create_context_calls == []
            assert _ssl_context_cache == {}
