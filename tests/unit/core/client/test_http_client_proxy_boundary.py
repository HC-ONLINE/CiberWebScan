"""HTTPClient proxy-boundary tests.

``HTTPClient.__init__`` is the single enforcement point for every HTTP
client (CLI, API, config fallback, rotation, helper clients): the
effective proxy is classified *before* ``httpx.Client`` is constructed,
so a forbidden proxy never reaches a transport. The ``httpx.Client``
factory is patched to record whether a transport would have been built —
that flag is the evidence of "no connection attempted".
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ciberwebscan.config.loader import get_config
from ciberwebscan.config.models import ProxyConfig
from ciberwebscan.core.client import HTTPClient
from ciberwebscan.core.client.ssrf import SSRFBlockedError

pytestmark = pytest.mark.unit


@pytest.fixture
def client_factory(monkeypatch: pytest.MonkeyPatch):
    """Patch httpx.Client, recording construction and capturing kwargs."""
    captured: dict[str, Any] = {"constructed": False, "kwargs": {}}
    real_client_cls = httpx.Client

    def factory(**kwargs: Any) -> httpx.Client:
        captured["constructed"] = True
        captured["kwargs"] = kwargs
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    return captured


def _legacy_config_proxy(**overrides: Any) -> ProxyConfig:
    """Build a ProxyConfig bypassing model validation.

    Simulates configuration that reached the singleton through a legacy
    path (or a fixture) without going through the ingestion validator, so
    the usage boundary is what gets exercised.
    """
    fields: dict[str, Any] = {
        "http": None,
        "https": None,
        "socks5": None,
        "rotate": False,
        "rotation_interval": 10,
        "proxy_list": None,
        "allow_local": False,
        "use_env": False,
    }
    fields.update(overrides)
    return ProxyConfig.model_construct(**fields)


class TestForbiddenProxyNeverReachesTransport:
    """Scenarios 1-4, 13: blocked before any transport exists."""

    @pytest.mark.parametrize(
        "proxy",
        [
            "http://127.0.0.1:8080",
            "http://10.0.0.5:3128",
            "http://169.254.169.254",
            "http://[::1]:1080",
            "http://2130706433:8080",
            "socks5://127.0.0.1:1080",
        ],
    )
    def test_loopback_private_imds_proxy_blocked_at_init(
        self, proxy: str, client_factory: dict[str, Any]
    ) -> None:
        with pytest.raises(SSRFBlockedError):
            HTTPClient(proxy=proxy)
        assert client_factory["constructed"] is False

    def test_config_fallback_proxy_is_validated(
        self, client_factory: dict[str, Any]
    ) -> None:
        """Scenario 14: a persistent config proxy is checked before use."""
        get_config().http.proxy = _legacy_config_proxy(
            https="http://169.254.169.254:80"
        )
        with pytest.raises(SSRFBlockedError):
            HTTPClient()
        assert client_factory["constructed"] is False

    def test_credentials_never_echoed(self) -> None:
        with pytest.raises(SSRFBlockedError) as exc:
            HTTPClient(proxy="http://user:S3cr3t@127.0.0.1:8080")
        assert "S3cr3t" not in str(exc.value)


class TestEnvironmentProxies:
    """Scenarios 15-16: trust_env is explicit and env proxies are policed."""

    def test_env_proxies_ignored_by_default(
        self, client_factory: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
        monkeypatch.setenv("HTTPS_PROXY", "http://169.254.169.254")
        client = HTTPClient()
        assert client_factory["constructed"] is True
        assert client_factory["kwargs"]["trust_env"] is False
        assert client_factory["kwargs"]["proxy"] is None
        client.close()

    def test_env_proxy_validated_when_enabled(
        self, client_factory: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
        with pytest.raises(SSRFBlockedError):
            HTTPClient(use_env_proxies=True)
        assert client_factory["constructed"] is False

    def test_lowercase_env_variant_validated_when_enabled(
        self, client_factory: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("all_proxy", "socks5://127.0.0.1:1080")
        with pytest.raises(SSRFBlockedError):
            HTTPClient(use_env_proxies=True)
        assert client_factory["constructed"] is False

    def test_public_env_proxy_accepted_when_enabled(
        self, client_factory: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.com:8080")
        client = HTTPClient(use_env_proxies=True)
        assert client_factory["constructed"] is True
        assert client_factory["kwargs"]["trust_env"] is True
        client.close()

    def test_config_use_env_flag_enables_env_honouring(
        self, client_factory: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_PROXY", "http://169.254.169.254")
        get_config().http.proxy = _legacy_config_proxy(use_env=True)
        with pytest.raises(SSRFBlockedError):
            HTTPClient()
        assert client_factory["constructed"] is False

    def test_explicit_proxy_supersedes_env(
        self, client_factory: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an explicit (validated) proxy httpx never consults env."""
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
        client = HTTPClient(proxy="http://proxy.example.com:8080", use_env_proxies=True)
        assert client_factory["constructed"] is True
        assert client_factory["kwargs"]["proxy"] == "http://proxy.example.com:8080"
        client.close()


class TestLocalProxyOptIn:
    """Scenario 10 + independence (scenario 18) at the boundary."""

    def test_allow_local_proxy_permits_loopback(
        self, client_factory: dict[str, Any]
    ) -> None:
        client = HTTPClient(proxy="http://127.0.0.1:8080", allow_local_proxy=True)
        assert client_factory["constructed"] is True
        client.close()

    def test_allow_local_proxy_still_blocks_imds(
        self, client_factory: dict[str, Any]
    ) -> None:
        with pytest.raises(SSRFBlockedError):
            HTTPClient(proxy="http://169.254.169.254:80", allow_local_proxy=True)
        assert client_factory["constructed"] is False

    def test_config_allow_local_proxy_opt_in(
        self, client_factory: dict[str, Any]
    ) -> None:
        get_config().http.proxy = ProxyConfig(
            allow_local=True, http="http://127.0.0.1:8080"
        )
        client = HTTPClient()
        assert client_factory["constructed"] is True
        client.close()

    def test_target_allow_local_does_not_permit_local_proxy(
        self, client_factory: dict[str, Any]
    ) -> None:
        with pytest.raises(SSRFBlockedError):
            HTTPClient(proxy="http://127.0.0.1:8080", ssrf_guard=True, allow_local=True)
        assert client_factory["constructed"] is False


class TestSocks5AndNoProxyClients:
    """Scenarios 9, 29: SOCKS5 is really supported; plain clients unchanged."""

    def test_socks5_proxy_client_is_constructible(
        self, client_factory: dict[str, Any]
    ) -> None:
        """httpx[socks] (socksio) is installed: no 'requires socksio' error."""
        client = HTTPClient(proxy="socks5://proxy.example.com:1080")
        assert client_factory["constructed"] is True
        client.close()

    def test_client_without_proxy_still_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_client_cls = httpx.Client

        def factory(**kwargs: Any) -> httpx.Client:
            kwargs["transport"] = httpx.MockTransport(
                lambda request: httpx.Response(200, text="ok")
            )
            return real_client_cls(**kwargs)

        monkeypatch.setattr(httpx, "Client", factory)
        client = HTTPClient()
        response = client.get("http://example.com/")
        assert response.status_code == 200
        client.close()
