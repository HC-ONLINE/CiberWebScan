"""Remote configuration authorization tests (BUG-014, P2).

Proxy options (``http.proxy.*``) and every security exception
(``*.allow_local``) are operator-only: they cannot be modified through
``PUT /api/config`` because API keys carry no administrative scope
distinction. The local operator keeps full control via the config file,
environment variables and the CLI (which never pass through this route).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.api.routes.config import config_update_touches_protected
from ciberwebscan.services.config_service import ConfigService

pytestmark = pytest.mark.unit


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect HOME/USERPROFILE so Path.home() lands in tmp."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    return fake_home


@pytest.fixture
def real_client(isolated_home: Path):
    """TestClient WITHOUT auth overrides: real API-key auth via global config."""
    app = create_app()
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers(isolated_home: Path) -> dict[str, str]:
    """Seed a known API key in the global config and return its auth headers."""
    key = "unit-test-api-key-1234567890"
    ConfigService().set("api.auth.api_keys", [key])
    return {"X-API-Key": key}


class TestProtectedKeysHelper:
    """Unit coverage of the protection predicate itself."""

    @pytest.mark.parametrize(
        "path",
        [
            "http.proxy",
            "http.proxy.http",
            "http.proxy.https",
            "http.proxy.socks5",
            "http.proxy.rotate",
            "http.proxy.rotation_interval",
            "http.proxy.proxy_list",
            "http.proxy.allow_local",
            "http.proxy.use_env",
            "HTTP.Proxy.HTTP",  # case variant
            "  http.proxy.use_env  ",  # whitespace variant
            "http.proxy.",  # trailing dot
            "analysis.allow_local",
            "scraping.allow_local",
            "attack.allow_local",
            "allow_local",  # bare exception key
        ],
    )
    def test_protected(self, path: str) -> None:
        assert config_update_touches_protected(path, "anything") is True

    @pytest.mark.parametrize(
        "path",
        [
            "http.timeout.connect",
            "http.retry.max_attempts",
            "http.tls.verify",
            "logging.level",
            "api.auth.api_keys",
            "scraping.dynamic.enabled",
        ],
    )
    def test_not_protected(self, path: str) -> None:
        assert config_update_touches_protected(path, "anything") is False

    @pytest.mark.parametrize(
        "path,value",
        [
            # Section updates smuggling protected subkeys
            ("http", {"proxy": {"allow_local": True}}),
            ("http", {"proxy": {"http": "http://evil.example.com:8080"}}),
            ("analysis", {"allow_local": True}),
            ("scraping", {"allow_local": True}),
            ("attack", {"allow_local": True}),
            # Deeply nested batch payloads
            ("", {"http": {"proxy": {"use_env": True}}}),
            ("", {"analysis": {"allow_local": True}}),
        ],
    )
    def test_batch_updates_protected(self, path: str, value: dict) -> None:
        assert config_update_touches_protected(path, value) is True

    def test_batch_update_with_only_allowed_keys(self) -> None:
        assert (
            config_update_touches_protected(
                "http", {"timeout": {"connect": 15.0}, "http2": True}
            )
            is False
        )


class TestRemoteUpdateRejected:
    """Scenarios 19-23: remote writes to protected keys always fail closed."""

    @pytest.mark.parametrize(
        "path,value",
        [
            ("http.proxy.http", "http://proxy.example.com:8080"),
            ("http.proxy.socks5", "socks5://proxy.example.com:1080"),
            ("http.proxy.rotate", True),
            ("http.proxy.proxy_list", ["http://proxy.example.com:8080"]),
            ("http.proxy.allow_local", True),
            ("http.proxy.use_env", True),
            ("HTTP.Proxy.Allow_Local", True),  # case variant
            ("analysis.allow_local", True),
            ("scraping.allow_local", True),
            ("attack.allow_local", True),
            # Batch/section updates
            ("http", {"proxy": {"allow_local": True}}),
            ("analysis", {"allow_local": True}),
        ],
    )
    def test_protected_update_returns_403(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        path: str,
        value: object,
    ) -> None:
        resp = real_client.put(
            "/api/config",
            json={"path": path, "value": value},
            headers=auth_headers,
        )
        assert resp.status_code == 403, resp.text
        detail = resp.json()["detail"]
        assert "protected" in detail.lower()
        # No configuration values or secrets leak back to the caller.
        assert "proxy.example.com" not in detail

    def test_protected_update_with_save_flag_rejected(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        tmp_path: Path,
    ) -> None:
        resp = real_client.put(
            "/api/config",
            json={"path": "http.proxy.allow_local", "value": True, "save": True},
            headers=auth_headers,
        )
        assert resp.status_code == 403, resp.text

    def test_value_not_applied_after_403(
        self, real_client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        from ciberwebscan.config.loader import get_config

        real_client.put(
            "/api/config",
            json={"path": "http.proxy.allow_local", "value": True},
            headers=auth_headers,
        )
        proxy = get_config().http.proxy
        assert proxy is None or proxy.allow_local is False

    def test_allowed_keys_still_updatable(
        self, real_client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": 15.0},
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["value"] == 15.0

    def test_unauthenticated_request_still_rejected(
        self, real_client: TestClient
    ) -> None:
        resp = real_client.put(
            "/api/config",
            json={"path": "http.proxy.allow_local", "value": True},
        )
        assert resp.status_code == 401

    def test_reset_of_protected_section_still_allowed(
        self, real_client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Reset restores safe defaults, so it is not a protected write."""
        from ciberwebscan.config.loader import get_config

        ConfigService().set("http.proxy.allow_local", True)
        resp = real_client.post(
            "/api/config/reset",
            json={"path": "http.proxy"},
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.text
        proxy = get_config().http.proxy
        assert proxy is None or proxy.allow_local is False
