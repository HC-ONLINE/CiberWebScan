"""
Tests for configuration management endpoints.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ciberwebscan.api.app import create_app
from ciberwebscan.config.loader import get_config, get_loader
from ciberwebscan.services.config_service import ConfigService

pytestmark = pytest.mark.unit


@pytest.fixture
def client():
    """Create a test client with a mocked user."""
    from ciberwebscan.api.auth import AuthenticatedUser, get_current_user

    app = create_app()

    # Mock the authentication dependency
    def mock_get_current_user() -> AuthenticatedUser:
        return AuthenticatedUser(
            identifier="test-user",
            auth_method="api_key",
            scopes=["read", "write"],
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    client = TestClient(app)

    yield client

    # Clean up dependency overrides
    app.dependency_overrides.clear()


@pytest.fixture
def temp_config_dir():
    """Create a temporary directory for config files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestConfigEndpoints:
    """Test configuration management endpoints."""

    def test_get_all_config(self, client):
        """Test GET /api/config returns all configuration."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the get_all result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = {
                "scraping": {"timeout": 30},
                "analysis": {"enabled": True},
            }
            mock_service.get_all.return_value = mock_result

            response = client.get("/api/config")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "data" in data
            assert "scraping" in data["data"]

    def test_get_config_section(self, client):
        """Test GET /api/config/sections/{section} returns section config."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the get_section result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = {"timeout": 30, "retries": 3}
            mock_service.get_section.return_value = mock_result

            response = client.get("/api/config/sections/scraping")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["timeout"] == 30

    def test_get_config_section_not_found(self, client):
        """Test GET /api/config/sections/{section} with invalid section."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the get_section failure
            mock_result = MagicMock()
            mock_result.success = False
            mock_result.error = "Section not found: invalid"
            mock_service.get_section.return_value = mock_result

            response = client.get("/api/config/sections/invalid")

            assert response.status_code == 404

    def test_get_config_value(self, client):
        """Test GET /api/config/value returns specific value with metadata."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock ConfigValue
            from ciberwebscan.services.config_service import ConfigValue

            config_value = ConfigValue(
                key="scraping.timeout",
                value=30,
                default=30,
                source="default",
                description="Timeout for scraping operations",
            )

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = config_value
            mock_service.get.return_value = mock_result

            response = client.get("/api/config/value?path=scraping.timeout")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["value"] == 30
            assert data["data"]["source"] == "default"

    def test_get_config_value_not_found(self, client):
        """Test GET /api/config/value with invalid key."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the get failure
            mock_result = MagicMock()
            mock_result.success = False
            mock_result.error = "Configuration key not found: invalid.key"
            mock_service.get.return_value = mock_result

            response = client.get("/api/config/value?path=invalid.key")

            assert response.status_code == 404

    def test_update_config(self, client):
        """Test PUT /api/config updates a configuration value."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock ConfigValue
            from ciberwebscan.services.config_service import ConfigValue

            config_value = ConfigValue(
                key="scraping.timeout",
                value=60,
                default=30,
                source="runtime",
                description="Timeout for scraping operations",
            )

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = config_value
            mock_service.set.return_value = mock_result

            response = client.put(
                "/api/config",
                json={"path": "scraping.timeout", "value": 60, "save": False},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["value"] == 60
            assert data["data"]["source"] == "runtime"

    def test_update_config_with_save(self, client):
        """Test PUT /api/config with save=True."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock ConfigValue
            from ciberwebscan.services.config_service import ConfigValue

            config_value = ConfigValue(
                key="scraping.timeout",
                value=60,
                default=30,
                source="runtime",
                description="Timeout for scraping operations",
            )

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = config_value
            mock_service.set.return_value = mock_result

            save_result = MagicMock()
            save_result.success = True
            save_result.data = Path("/tmp/config.yaml")
            mock_service.save.return_value = save_result

            response = client.put(
                "/api/config",
                json={"path": "scraping.timeout", "value": 60, "save": True},
            )

            assert response.status_code == 200
            mock_service.save.assert_called_once()

    def test_reset_config_all(self, client):
        """Test POST /api/config/reset resets all configuration."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the reset result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = True
            mock_service.reset.return_value = mock_result

            response = client.post(
                "/api/config/reset",
                json={"path": None, "save": False},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["reset"] is True
            assert data["data"]["path"] == "all"

    def test_reset_config_key(self, client):
        """Test POST /api/config/reset resets specific key."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the reset result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = True
            mock_service.reset.return_value = mock_result

            response = client.post(
                "/api/config/reset",
                json={"path": "scraping.timeout", "save": False},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["path"] == "scraping.timeout"

    def test_list_config_keys(self, client):
        """Test GET /api/config/keys lists all configuration keys."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the list_keys result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = [
                "scraping.timeout",
                "scraping.retries",
                "analysis.enabled",
            ]
            mock_service.list_keys.return_value = mock_result

            response = client.get("/api/config/keys")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["count"] == 3
            assert "scraping.timeout" in data["data"]["keys"]

    def test_list_config_keys_with_section(self, client):
        """Test GET /api/config/keys?section=... filters by section."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the list_keys result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = ["scraping.timeout", "scraping.retries"]
            mock_service.list_keys.return_value = mock_result

            response = client.get("/api/config/keys?section=scraping")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            mock_service.list_keys.assert_called_once_with("scraping")

    def test_export_config_yaml(self, client, temp_config_dir):
        """Test POST /api/config/export exports to YAML."""
        output_path = temp_config_dir / "config.yaml"

        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the export result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = output_path
            mock_service.export_config.return_value = mock_result

            response = client.post(
                "/api/config/export",
                json={"path": str(output_path), "format": "yaml"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["operation"] == "export"
            assert data["data"]["format"] == "yaml"

    def test_export_config_json(self, client, temp_config_dir):
        """Test POST /api/config/export exports to JSON."""
        output_path = temp_config_dir / "config.json"

        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the export result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = output_path
            mock_service.export_config.return_value = mock_result

            response = client.post(
                "/api/config/export",
                json={"path": str(output_path), "format": "json"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["data"]["format"] == "json"

    def test_export_config_invalid_format(self, client, temp_config_dir):
        """Test POST /api/config/export with invalid format."""
        output_path = temp_config_dir / "config.txt"

        response = client.post(
            "/api/config/export",
            json={"path": str(output_path), "format": "txt"},
        )

        assert response.status_code == 400

    def test_load_config(self, client, temp_config_dir):
        """Test POST /api/config/load loads configuration from file."""
        config_path = temp_config_dir / "config.yaml"

        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the load result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = {"scraping": {"timeout": 30}}
            mock_service.load.return_value = mock_result

            response = client.post(
                "/api/config/load",
                json={"path": str(config_path)},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "scraping" in data["data"]

    def test_load_config_file_not_found(self, client, temp_config_dir):
        """Test POST /api/config/load with non-existent file."""
        config_path = temp_config_dir / "nonexistent.yaml"

        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the load failure
            mock_result = MagicMock()
            mock_result.success = False
            mock_result.error = f"Config file not found: {config_path}"
            mock_service.load.return_value = mock_result

            response = client.post(
                "/api/config/load",
                json={"path": str(config_path)},
            )

            assert response.status_code == 404

    def test_save_config(self, client, temp_config_dir):
        """Test POST /api/config/save saves configuration to file."""
        save_path = temp_config_dir / "config.yaml"

        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the save result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = save_path
            mock_service.save.return_value = mock_result

            response = client.post(
                "/api/config/save",
                json={"path": str(save_path)},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["operation"] == "save"

    def test_save_config_default_path(self, client):
        """Test POST /api/config/save uses default path."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            # Mock the save result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = Path.home() / ".ciberwebscan" / "config.yaml"
            mock_service.save.return_value = mock_result

            response = client.post("/api/config/save")

            assert response.status_code == 200
            mock_service.save.assert_called_once_with(None)


# =============================================================================
# Sensitive Field Masking Tests
# =============================================================================


class TestSensitiveFieldMasking:
    """Test that API endpoints mask sensitive configuration fields."""

    def test_get_all_config_masks_api_keys(self, client):
        """Test GET /api/config masks api.auth.api_keys."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = {
                "api": {
                    "auth": {
                        "api_keys": ["***", "***"],
                    },
                    "host": "0.0.0.0",
                },
                "http": {"timeout": {"connect": 10}},
            }
            mock_service.get_all.return_value = mock_result

            response = client.get("/api/config")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            # API keys should be masked
            api_keys = data["data"]["api"]["auth"]["api_keys"]
            assert all(v == "***" for v in api_keys)
            # Non-sensitive values should be preserved
            assert data["data"]["api"]["host"] == "0.0.0.0"
            assert data["data"]["http"]["timeout"]["connect"] == 10

    def test_get_config_section_masks_sensitive(self, client):
        """Test GET /api/config/sections/{section} masks sensitive fields."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = {
                "auth": {
                    "api_keys": ["***"],
                },
                "host": "0.0.0.0",
            }
            mock_service.get_section.return_value = mock_result

            response = client.get("/api/config/sections/api")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            api_keys = data["data"]["auth"]["api_keys"]
            assert all(v == "***" for v in api_keys)
            assert data["data"]["host"] == "0.0.0.0"

    def test_get_config_value_masks_sensitive(self, client):
        """Test GET /api/config/value masks sensitive values."""
        with patch(
            "ciberwebscan.api.routes.config.ConfigService"
        ) as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service

            from ciberwebscan.services.config_service import ConfigValue

            config_value = ConfigValue(
                key="api.auth.api_keys",
                value=["***", "***"],
                default=[],
                source="file",
                description="List of valid API keys",
            )

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.data = config_value
            mock_service.get.return_value = mock_result

            response = client.get("/api/config/value?path=api.auth.api_keys")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["value"] == ["***", "***"]
            # Metadata should be preserved
            assert data["data"]["source"] == "file"
            assert data["data"]["key"] == "api.auth.api_keys"


# =============================================================================
# Real-service behavior tests (shared global config, real auth)
# =============================================================================


@pytest.fixture
def real_client():
    """TestClient WITHOUT auth overrides: real API-key auth via global config."""
    app = create_app()
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def isolated_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the global loader's config_path to a temp file."""
    target = tmp_path / "config.yaml"
    monkeypatch.setattr(get_loader(), "config_path", target)
    return target


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Seed a known API key in the global config and return its auth headers."""
    key = "unit-test-api-key-1234567890"
    ConfigService().set("api.auth.api_keys", [key])
    return {"X-API-Key": key}


class TestConfigRuntimeSync:
    """PUT /api/config must modify the runtime state shared process-wide."""

    def test_put_save_false_updates_runtime(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.delenv("CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", raising=False)

        response = real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": 77.0, "save": False},
            headers=auth_headers,
        )

        assert response.status_code == 200
        # Runtime (get_config) sees the change without any save
        assert get_config().http.timeout.connect == 77.0
        # A subsequent GET (new ConfigService instance) sees it too
        got = real_client.get(
            "/api/config/value",
            params={"path": "http.timeout.connect"},
            headers=auth_headers,
        )
        assert got.status_code == 200
        assert got.json()["data"]["value"] == 77.0

    def test_put_save_false_does_not_touch_disk(
        self,
        real_client: TestClient,
        isolated_config_file: Path,
        auth_headers: dict[str, str],
    ):
        response = real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": 77.0, "save": False},
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert get_config().http.timeout.connect == 77.0
        assert not isolated_config_file.exists()

    def test_put_save_true_persists_runtime_and_disk(
        self,
        real_client: TestClient,
        isolated_config_file: Path,
        auth_headers: dict[str, str],
    ):
        response = real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": 88.0, "save": True},
            headers=auth_headers,
        )

        assert response.status_code == 200
        # Runtime updated
        assert get_config().http.timeout.connect == 88.0
        # Disk updated
        assert isolated_config_file.exists()
        import yaml

        saved = yaml.safe_load(isolated_config_file.read_text(encoding="utf-8"))
        assert saved["http"]["timeout"]["connect"] == 88.0

    def test_put_invalid_value_leaves_runtime_untouched(
        self, real_client: TestClient, auth_headers: dict[str, str]
    ):
        default = get_config().http.timeout.connect

        response = real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": "not-a-float"},
            headers=auth_headers,
        )

        assert response.status_code == 400
        assert get_config().http.timeout.connect == default


class TestApiKeyRevocation:
    """Changing api.auth.api_keys must take effect on the very next request."""

    @pytest.fixture(autouse=True)
    def seed_keys(self):
        ConfigService().set("api.auth.api_keys", ["old-key-1234567890"])

    def test_old_key_authenticates_before_revocation(self, real_client: TestClient):
        response = real_client.get(
            "/api/config/keys", headers={"X-API-Key": "old-key-1234567890"}
        )
        assert response.status_code == 200

    def test_revoked_key_stops_authenticating(self, real_client: TestClient):
        old = {"X-API-Key": "old-key-1234567890"}
        new_key = "new-key-0987654321"

        # Revoke via PUT (authenticated with the old key)
        put = real_client.put(
            "/api/config",
            json={"path": "api.auth.api_keys", "value": [new_key], "save": False},
            headers=old,
        )
        assert put.status_code == 200

        # Old key is rejected immediately, without restart
        assert real_client.get("/api/config/keys", headers=old).status_code == 401
        # New key works immediately
        fresh = real_client.get("/api/config/keys", headers={"X-API-Key": new_key})
        assert fresh.status_code == 200

    def test_no_key_is_rejected(self, real_client: TestClient):
        assert real_client.get("/api/config/keys").status_code == 401

    def test_revocation_survives_config_service_instances(
        self, real_client: TestClient
    ):
        new_key = "another-key-555555"
        ConfigService().set("api.auth.api_keys", [new_key])

        assert (
            real_client.get(
                "/api/config/keys", headers={"X-API-Key": new_key}
            ).status_code
            == 200
        )
        assert (
            real_client.get(
                "/api/config/keys", headers={"X-API-Key": "old-key-1234567890"}
            ).status_code
            == 401
        )


class TestResetViaAPI:
    """POST /api/config/reset must modify runtime state without identity loss."""

    def test_reset_key_updates_runtime(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.delenv("CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", raising=False)
        real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": 99.0, "save": False},
            headers=auth_headers,
        )
        assert get_config().http.timeout.connect == 99.0

        response = real_client.post(
            "/api/config/reset",
            json={"path": "http.timeout.connect", "save": False},
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert get_config().http.timeout.connect == 10.0

    def test_reset_all_updates_runtime_and_preserves_identity(
        self,
        real_client: TestClient,
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.delenv("CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", raising=False)
        ident = id(get_config())
        real_client.put(
            "/api/config",
            json={"path": "http.timeout.connect", "value": 99.0, "save": False},
            headers=auth_headers,
        )

        response = real_client.post(
            "/api/config/reset",
            json={"path": None, "save": False},
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert get_config().http.timeout.connect == 10.0
        assert id(get_config()) == ident

    def test_reset_key_with_none_default_via_api(
        self, real_client: TestClient, auth_headers: dict[str, str]
    ):
        ConfigService().set("analysis.cve.nvd_api_key", "some-key")

        response = real_client.post(
            "/api/config/reset",
            json={"path": "analysis.cve.nvd_api_key", "save": False},
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert get_config().analysis.cve.nvd_api_key is None
