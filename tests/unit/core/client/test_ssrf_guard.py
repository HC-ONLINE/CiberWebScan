"""SSRF request-guard tests for HTTPClient (BUG-004).

The guard is a synchronous ``httpx`` request event hook: it runs before
every request httpx sends, including each redirect hop, so a blocked hop
is never written to the wire. These tests use ``httpx.MockTransport`` and
record exactly which URLs reached the transport as evidence.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from ciberwebscan.core.client import HTTPClient
from ciberwebscan.core.client.ssrf import SSRFBlockedError


def _build_guarded_client(
    monkeypatch: pytest.MonkeyPatch,
    handler,
    **overrides: Any,
) -> tuple[HTTPClient, dict[str, Any]]:
    """Build an HTTPClient whose httpx.Client uses *handler*.

    Returns the client plus the kwargs that were handed to ``httpx.Client``
    (so tests can inspect the registered event hooks).
    """
    captured: dict[str, Any] = {}
    real_client_cls = httpx.Client

    def factory(**kwargs: Any) -> httpx.Client:
        captured.clear()
        captured.update(kwargs)
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "Client", factory)

    defaults: dict[str, Any] = {
        "max_attempts": 0,
        "rate_limit": 0,
        "http2": False,
        "follow_redirects": True,
    }
    defaults.update(overrides)
    client = HTTPClient(**defaults)
    return client, captured


class TestGuardedRedirects:
    """Redirect hops are validated before they are sent."""

    def test_redirect_to_metadata_blocked_and_never_requested(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            if request.url.host == "public.test":
                return httpx.Response(
                    302,
                    headers={"location": "http://169.254.169.254/latest/meta-data/"},
                )
            return httpx.Response(200, text="secret")

        client, _ = _build_guarded_client(monkeypatch, handler, ssrf_guard=True)

        with pytest.raises(SSRFBlockedError) as exc_info:
            client.get("http://public.test/")

        assert "ssrf" in str(exc_info.value).lower()
        # Evidence: only the first hop reached the transport; the
        # link-local metadata hop was never sent.
        assert requested == ["http://public.test/"]

    def test_redirect_to_loopback_blocked_and_never_requested(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            if request.url.host == "public.test":
                return httpx.Response(
                    302, headers={"location": "http://127.0.0.1:9200/_cat/indices"}
                )
            return httpx.Response(200, text="ok")

        client, _ = _build_guarded_client(monkeypatch, handler, ssrf_guard=True)

        with pytest.raises(SSRFBlockedError):
            client.get("http://public.test/")
        assert requested == ["http://public.test/"]

    def test_public_redirect_chain_still_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            if request.url.host == "public.test":
                return httpx.Response(
                    302, headers={"location": "http://public-next.test/page"}
                )
            return httpx.Response(200, text="final")

        client, _ = _build_guarded_client(monkeypatch, handler, ssrf_guard=True)

        response = client.get("http://public.test/")
        assert response.status_code == 200
        assert response.text == "final"
        assert requested == [
            "http://public.test/",
            "http://public-next.test/page",
        ]

    def test_initial_request_to_private_target_blocked_before_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            return httpx.Response(200, text="should not happen")

        client, _ = _build_guarded_client(monkeypatch, handler, ssrf_guard=True)

        with pytest.raises(SSRFBlockedError):
            client.get("http://169.254.169.254/latest/meta-data/")
        assert requested == []

    def test_hostname_resolving_to_loopback_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            if request.url.host == "public.test":
                return httpx.Response(302, headers={"location": "http://localtest.me/"})
            return httpx.Response(200, text="loopback content")

        client, _ = _build_guarded_client(monkeypatch, handler, ssrf_guard=True)

        with pytest.raises(SSRFBlockedError):
            client.get("http://public.test/")
        assert requested == ["http://public.test/"]


class TestGuardConfiguration:
    """Guard is opt-in and configurable."""

    def test_guard_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            return httpx.Response(200, text="unguarded")

        client, captured = _build_guarded_client(monkeypatch, handler)
        response = client.get("http://169.254.169.254/")
        assert response.status_code == 200
        assert requested == ["http://169.254.169.254/"]
        assert captured.get("event_hooks", {}).get("request", []) == []

    def test_guard_registers_a_synchronous_hook(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """httpx only awaits async hooks in async mode: a coroutine hook
        in the sync client would silently never run."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok")

        _, captured = _build_guarded_client(monkeypatch, handler, ssrf_guard=True)
        hooks = captured["event_hooks"]["request"]
        assert len(hooks) == 1
        assert not asyncio.iscoroutinefunction(hooks[0])

    def test_allow_local_permits_metadata_redirect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "public.test":
                return httpx.Response(
                    302,
                    headers={"location": "http://169.254.169.254/latest/meta-data/"},
                )
            return httpx.Response(200, text="internal")

        client, _ = _build_guarded_client(
            monkeypatch, handler, ssrf_guard=True, allow_local=True
        )
        response = client.get("http://public.test/")
        assert response.status_code == 200
        assert response.text == "internal"
