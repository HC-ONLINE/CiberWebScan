"""ProxyConfig ingestion-policy tests.

Every proxy that reaches the configuration model is classified at
ingestion time with the same central policy used at the usage boundary,
so ``proxy_list`` as a string and as a list behave identically. Invalid
environment overrides degrade the whole config to defaults with an
explicit error log — never to an unvalidated proxy.
"""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from ciberwebscan.config.loader import get_config, reset_config
from ciberwebscan.config.models import ProxyConfig

pytestmark = pytest.mark.unit


class TestProxyListConsistency:
    """Scenario 11: string and list forms are equally policed."""

    def test_list_with_loopback_rejected(self) -> None:
        with pytest.raises(ValidationError, match="SSRF"):
            ProxyConfig(proxy_list=["http://127.0.0.1:8080"])

    def test_string_with_loopback_rejected(self) -> None:
        with pytest.raises(ValidationError, match="SSRF"):
            ProxyConfig(proxy_list="http://127.0.0.1:8080")

    def test_string_and_list_reject_the_same_entry(self) -> None:
        entry = "http://169.254.169.254"
        with pytest.raises(ValidationError):
            ProxyConfig(proxy_list=[entry])
        with pytest.raises(ValidationError):
            ProxyConfig(proxy_list=entry)

    def test_mixed_string_list_with_loopback_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ProxyConfig(
                proxy_list="http://proxy.example.com:8080, http://10.0.0.5:3128"
            )

    def test_string_and_list_accepted_with_opt_in(self) -> None:
        from_list = ProxyConfig(proxy_list=["http://127.0.0.1:8080"], allow_local=True)
        from_string = ProxyConfig(
            proxy_list="http://127.0.0.1:8080, http://192.168.1.10:3128",
            allow_local=True,
        )
        assert from_list.proxy_list == ["http://127.0.0.1:8080"]
        assert from_string.proxy_list == [
            "http://127.0.0.1:8080",
            "http://192.168.1.10:3128",
        ]

    def test_public_list_accepted(self) -> None:
        config = ProxyConfig(
            proxy_list=["http://proxy.example.com:8080"], allow_local=False
        )
        assert config.proxy_list == ["http://proxy.example.com:8080"]


class TestIndividualProxyFields:
    """Scenario 12: http/https/socks5 fields go through the same policy."""

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"http": "http://127.0.0.1:8080"},
            {"https": "http://10.0.0.5:3128"},
            {"socks5": "socks5://127.0.0.1:1080"},
        ],
    )
    def test_private_proxy_fields_rejected_by_default(self, kwargs: dict) -> None:
        with pytest.raises(ValidationError, match="SSRF"):
            ProxyConfig(**kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"http": "http://127.0.0.1:8080"},
            {"https": "http://10.0.0.5:3128"},
            {"socks5": "socks5://192.168.1.10:1080"},
        ],
    )
    def test_private_proxy_fields_accepted_with_opt_in(self, kwargs: dict) -> None:
        config = ProxyConfig(allow_local=True, **kwargs)
        assert config.allow_local is True

    @pytest.mark.parametrize("allow_local", [False, True])
    def test_imds_rejected_even_with_opt_in(self, allow_local: bool) -> None:
        with pytest.raises(ValidationError, match="SSRF"):
            ProxyConfig(allow_local=allow_local, http="http://169.254.169.254")

    def test_public_fields_accepted(self) -> None:
        config = ProxyConfig(
            http="http://proxy.example.com:8080",
            socks5="socks5://proxy.example.com:1080",
        )
        assert config.http is not None
        assert config.socks5 == "socks5://proxy.example.com:1080"

    def test_defaults_have_no_proxy_and_safe_flags(self) -> None:
        config = ProxyConfig()
        assert config.http is None
        assert config.https is None
        assert config.socks5 is None
        assert config.proxy_list is None
        assert config.allow_local is False
        assert config.use_env is False


class TestEnvironmentOverrides:
    """Scenario 17: invalid config degrades loudly, never silently."""

    def test_env_enables_local_proxy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CIBERWEBSCAN_HTTP_PROXY_ALLOW_LOCAL", "true")
        monkeypatch.setenv("CIBERWEBSCAN_HTTP_PROXY_HTTP", "http://127.0.0.1:8080")
        reset_config()
        proxy = get_config().http.proxy
        assert proxy is not None
        assert proxy.allow_local is True
        assert str(proxy.http).startswith("http://127.0.0.1:8080")

    def test_env_rejects_imds_even_with_local_opt_in(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("CIBERWEBSCAN_HTTP_PROXY_ALLOW_LOCAL", "true")
        monkeypatch.setenv("CIBERWEBSCAN_HTTP_PROXY_HTTP", "http://169.254.169.254:80")
        reset_config()
        with caplog.at_level(logging.ERROR, logger="ciberwebscan.config.loader"):
            config = get_config()
        # Fallback to defaults: no proxy at all, with an explicit error log.
        assert config.http.proxy is None
        assert any(
            "Invalid configuration" in record.message for record in caplog.records
        )

    def test_env_rejects_private_proxy_without_opt_in(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("CIBERWEBSCAN_HTTP_PROXY_HTTP", "http://10.0.0.5:3128")
        reset_config()
        with caplog.at_level(logging.ERROR, logger="ciberwebscan.config.loader"):
            config = get_config()
        assert config.http.proxy is None
        assert any(
            "Invalid configuration" in record.message for record in caplog.records
        )
