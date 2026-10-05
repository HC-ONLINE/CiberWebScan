"""Path behavior of the /api/config endpoints (CONFIG_DIR sandbox).

The API resolves every per-call file path inside ``~/.ciberwebscan``: relative
paths, traversal attempts, absolute paths outside the base, wrong extensions
and ``~`` escapes are all rejected with 4xx, never written into the CWD.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
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


@pytest.fixture
def config_base(tmp_path: Path):
    """Patch the CONFIG_DIR sandbox base to a temp directory."""
    base = tmp_path / "apibase"
    base.mkdir()
    with patch(
        "ciberwebscan.services.config_service.get_config_base_dir",
        return_value=base,
    ):
        yield base


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated CWD: proves API paths never leak into the working directory."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


def _write(path: Path, connect: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"http:\n  timeout:\n    connect: {connect}\n",
        encoding="utf-8",
    )
    return path


class TestSandbox:
    """Relative, traversal, absolute, extension and type rules under CONFIG_DIR."""

    def test_relative_export_stays_in_base(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
        workdir: Path,
    ):
        resp = real_client.post(
            "/api/config/export",
            json={"path": "rel.yaml", "format": "yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()["data"]
        assert data["operation"] == "export"
        assert data["format"] == "yaml"
        assert Path(data["file_path"]).resolve() == (config_base / "rel.yaml").resolve()
        assert (config_base / "rel.yaml").is_file()
        assert not (workdir / "rel.yaml").exists()

    def test_parent_traversal_rejected(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
        workdir: Path,
    ):
        resp = real_client.post(
            "/api/config/export",
            json={"path": "../evil.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 400, resp.text
        assert "configuration path" in resp.json()["detail"].lower()
        assert not (config_base.parent / "evil.yaml").exists()
        assert not (workdir.parent / "evil.yaml").exists()

    def test_absolute_path_outside_base_rejected(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
        tmp_path: Path,
    ):
        outside = tmp_path / "outside.yaml"

        resp = real_client.post(
            "/api/config/export",
            json={"path": str(outside)},
            headers=auth_headers,
        )

        assert resp.status_code == 400, resp.text
        assert "configuration path" in resp.json()["detail"].lower()
        assert not outside.exists()

    def test_wrong_extension_rejected(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
    ):
        resp = real_client.post(
            "/api/config/export",
            json={"path": "evil.txt"},
            headers=auth_headers,
        )

        assert resp.status_code == 400, resp.text
        assert "extension" in resp.json()["detail"].lower()
        assert not (config_base / "evil.txt").exists()

    def test_null_byte_rejected(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
    ):
        resp = real_client.post(
            "/api/config/load",
            json={"path": "bad\0name.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 400, resp.text
        assert "null byte" in resp.json()["detail"].lower()

    def test_load_missing_returns_404(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
    ):
        resp = real_client.post(
            "/api/config/load",
            json={"path": "missing.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 404, resp.text
        assert "not found" in resp.json()["detail"].lower()

    def test_load_directory_returns_400(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
    ):
        (config_base / "dir.yaml").mkdir()

        resp = real_client.post(
            "/api/config/load",
            json={"path": "dir.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 400, resp.text
        assert "not a file" in resp.json()["detail"].lower()

    def test_save_with_path_lands_in_base(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
        workdir: Path,
    ):
        resp = real_client.post(
            "/api/config/save",
            json={"path": "mysave.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()["data"]
        assert data["operation"] == "save"
        assert (
            Path(data["file_path"]).resolve() == (config_base / "mysave.yaml").resolve()
        )
        assert (config_base / "mysave.yaml").is_file()
        assert not (workdir / "mysave.yaml").exists()

    def test_save_without_body_defaults_to_home_config(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        isolated_home: Path,
    ):
        resp = real_client.post("/api/config/save", headers=auth_headers)

        assert resp.status_code == 200, resp.text
        data = resp.json()["data"]
        expected = isolated_home / ".ciberwebscan" / "config.yaml"
        assert Path(data["file_path"]).resolve() == expected.resolve()
        assert expected.is_file()


class TestTildeExpansion:
    """``~`` is expanded before containment (real get_config_base_dir)."""

    def test_tilde_inside_base_accepted(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        isolated_home: Path,
        workdir: Path,
    ):
        resp = real_client.post(
            "/api/config/export",
            json={"path": "~/.ciberwebscan/tilde.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 200, resp.text
        expected = isolated_home / ".ciberwebscan" / "tilde.yaml"
        assert Path(resp.json()["data"]["file_path"]).resolve() == expected.resolve()
        assert expected.is_file()
        base = isolated_home / ".ciberwebscan"
        assert not (base / "~").exists()
        assert not (workdir / "~").exists()

    def test_tilde_outside_base_rejected(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        isolated_home: Path,
    ):
        resp = real_client.post(
            "/api/config/export",
            json={"path": "~/otro.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 400, resp.text
        base = isolated_home / ".ciberwebscan"
        assert not (base / "~").exists()
        assert not (isolated_home / "otro.yaml").exists()


class TestAuth:
    """Config file endpoints keep API-key auth."""

    def test_missing_api_key_returns_401(self, real_client: TestClient):
        resp = real_client.post("/api/config/export", json={"path": "x.yaml"})

        assert resp.status_code == 401


class TestRequestContracts:
    """The request/response fields documented in docs/API.md must match code."""

    def test_update_uses_path_value_save(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
    ):
        resp = real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": 7.5, "save": False},
            headers=auth_headers,
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()["data"]
        assert data["key"] == "http.timeout.connect"
        assert data["value"] == 7.5
        assert "file_path" not in data

        legacy = real_client.put(
            "/api/config",
            json={"updates": {"http.timeout.connect": 7.5}},
            headers=auth_headers,
        )
        assert legacy.status_code == 422

    def test_load_requires_path_field(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
    ):
        _write(config_base / "ok.yaml", 13)

        # Unknown field first: a successful load() replaces the global config
        # (API keys revert to defaults), which would break auth afterwards.
        legacy = real_client.post(
            "/api/config/load",
            json={"file_path": "ok.yaml"},
            headers=auth_headers,
        )
        assert legacy.status_code == 422

        ok = real_client.post(
            "/api/config/load",
            json={"path": "ok.yaml"},
            headers=auth_headers,
        )
        assert ok.status_code == 200, ok.text
        assert "file_path" not in ok.json()["data"]

    def test_save_response_has_file_path_only(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
    ):
        resp = real_client.post(
            "/api/config/save",
            json={"path": "contract.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()["data"]
        assert set(data) == {"file_path", "operation", "format"}
        assert data["operation"] == "save"


class TestServiceConstruction:
    """Handlers build ConfigService() bare; request.path goes to save()."""

    def test_handlers_build_service_without_arguments(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
    ):
        service = Mock()
        service.export_config.return_value = Mock(
            success=True, data=Path("out.yaml"), error=None, warnings=[]
        )
        service.load.return_value = Mock(
            success=True, data={"http": {}}, error=None, warnings=[]
        )
        service.save.return_value = Mock(
            success=True, data=Path("saved.yaml"), error=None, warnings=[]
        )

        with patch(
            "ciberwebscan.api.routes.config.ConfigService", return_value=service
        ) as mock_cls:
            exported = real_client.post(
                "/api/config/export",
                json={"path": "any.yaml"},
                headers=auth_headers,
            )
            assert exported.status_code == 200, exported.text
            assert mock_cls.call_args.args == ()
            assert mock_cls.call_args.kwargs == {}

            loaded = real_client.post(
                "/api/config/load",
                json={"path": "any.yaml"},
                headers=auth_headers,
            )
            assert loaded.status_code == 200, loaded.text
            assert mock_cls.call_args.args == ()
            assert mock_cls.call_args.kwargs == {}

            saved = real_client.post(
                "/api/config/save",
                json={"path": "any.yaml"},
                headers=auth_headers,
            )
            assert saved.status_code == 200, saved.text
            assert mock_cls.call_args.args == ()
            assert mock_cls.call_args.kwargs == {}
            # The request path is a per-call argument, never a constructor one.
            assert service.save.call_args.args == ("any.yaml",)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="symlink creation requires privileges on Windows",
)
class TestSymlinkEscape:
    """A symlink inside the base that points outside is rejected after resolve."""

    def test_symlink_escape_rejected(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        config_base: Path,
    ):
        outside = config_base.parent / "outside.yaml"
        _write(outside, 3)
        os.symlink(outside, config_base / "link.yaml")

        resp = real_client.post(
            "/api/config/load",
            json={"path": "link.yaml"},
            headers=auth_headers,
        )

        assert resp.status_code == 400, resp.text
        assert "configuration path" in resp.json()["detail"].lower()
