"""
Tests for ConfigService synchronization with the global config loader.

Covers the invariants of the shared-state architecture:
- ConfigService() operates on the same object as get_config()
- set/reset/load mutate the global object in place (identity preserved)
- ConfigService(config_path=...) stays isolated from the global state
- Invalid values never reach the (possibly global) config object
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ciberwebscan.config.loader import (
    ConfigLoader,
    get_config,
    get_loader,
    reset_config,
)
from ciberwebscan.config.models import AppConfig
from ciberwebscan.services.config_service import ConfigService

pytestmark = pytest.mark.unit


@pytest.fixture
def config_service() -> ConfigService:
    return ConfigService()


@pytest.fixture(autouse=True)
def mock_config_base_dir(tmp_path: Path):
    """Mock get_config_base_dir to use tmp_path for load/export path checks."""
    with patch(
        "ciberwebscan.services.config_service.get_config_base_dir",
        return_value=tmp_path,
    ):
        yield tmp_path


# =============================================================================
# Global mode: identity and synchronization
# =============================================================================


class TestGlobalIdentity:
    """ConfigService() must share the global loader and config object."""

    def test_config_is_get_config(self, config_service: ConfigService):
        assert config_service.config is get_config()

    def test_loader_is_get_loader(self, config_service: ConfigService):
        assert config_service.loader is get_loader()

    def test_config_path_matches_global_loader(self, config_service: ConfigService):
        assert config_service.config_path == get_loader().config_path

    def test_two_services_share_the_same_config(self):
        first = ConfigService()
        second = ConfigService()
        assert first.config is second.config is get_config()


class TestSetGlobalSync:
    """set() must mutate the global config immediately."""

    def test_set_updates_global_config(self, config_service: ConfigService):
        result = config_service.set("http.timeout.connect", 42.0)

        assert result.success is True
        assert get_config().http.timeout.connect == 42.0

    def test_set_preserves_config_identity(self, config_service: ConfigService):
        ident = id(get_config())

        config_service.set("http.timeout.connect", 42.0)

        assert id(get_config()) == ident
        assert id(config_service.config) == ident

    def test_set_without_save_is_visible_to_runtime_consumers(
        self, config_service: ConfigService
    ):
        result = config_service.set("http.timeout.connect", 42.0)

        assert result.success is True
        # A fresh service (like a new API request) sees the change
        assert ConfigService().get("http.timeout.connect").data.value == 42.0

    def test_set_source_runtime_after_sync(self, config_service: ConfigService):
        result = config_service.set("http.timeout.connect", 42.0)

        assert result.data.source == "runtime"


class TestSetValidation:
    """Invalid values must never reach the global config object."""

    def test_invalid_value_rejected(self, config_service: ConfigService):
        default = get_config().http.timeout.connect

        result = config_service.set("http.timeout.connect", "not-a-number")

        assert result.success is False
        assert result.error_code == "CONFIG_INVALID_VALUE"
        assert get_config().http.timeout.connect == default

    def test_invalid_value_rejected_on_explicit_service(self, tmp_path: Path):
        service = ConfigService(config_path=tmp_path / "config.yaml")
        default = service.config.http.timeout.connect

        result = service.set("http.timeout.connect", "not-a-number")

        assert result.success is False
        assert result.error_code == "CONFIG_INVALID_VALUE"
        assert service.config.http.timeout.connect == default

    def test_valid_coerced_value_is_applied(self, config_service: ConfigService):
        # int input coerced to float by the model
        result = config_service.set("http.timeout.connect", 42)

        assert result.success is True
        assert get_config().http.timeout.connect == 42.0

    def test_unknown_key_still_rejected(self, config_service: ConfigService):
        result = config_service.set("nonexistent.key", 1)

        assert result.success is False
        assert result.error_code == "CONFIG_KEY_NOT_FOUND"


class TestResetGlobalSync:
    """reset() must mutate the global config in place."""

    def test_reset_all_restores_defaults(
        self, config_service: ConfigService, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.delenv("CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", raising=False)
        reset_config()
        config_service = ConfigService()
        config_service.set("http.timeout.connect", 99.0)

        result = config_service.reset()

        assert result.success is True
        assert get_config().http.timeout.connect == 10.0

    def test_reset_all_preserves_identity(self, config_service: ConfigService):
        ident = id(get_config())
        config_service.set("http.timeout.connect", 99.0)

        result = config_service.reset()

        assert result.success is True
        assert id(get_config()) == ident

    def test_reset_all_uses_defaults_plus_env(
        self, config_service: ConfigService, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", "55.5")
        reset_config()
        config_service = ConfigService()
        config_service.set("http.timeout.connect", 99.0)

        result = config_service.reset()

        assert result.success is True
        # Env override wins over the pure default after reset
        assert get_config().http.timeout.connect == 55.5

    def test_reset_key_with_none_default_succeeds(self, config_service: ConfigService):
        # nvd_api_key defaults to None; reset must not confuse it with
        # "key not found"
        config_service.set("analysis.cve.nvd_api_key", "some-key")

        result = config_service.reset("analysis.cve.nvd_api_key")

        assert result.success is True
        assert get_config().analysis.cve.nvd_api_key is None

    def test_reset_unknown_key_fails(self, config_service: ConfigService):
        result = config_service.reset("nonexistent.key")

        assert result.success is False
        assert result.error_code == "CONFIG_KEY_NOT_FOUND"

    def test_reset_key_preserves_identity(self, config_service: ConfigService):
        ident = id(get_config())
        config_service.set("http.timeout.connect", 99.0)

        config_service.reset("http.timeout.connect")

        assert id(get_config()) == ident
        assert get_config().http.timeout.connect == 10.0

    def test_reset_flag_makes_save_write_empty_file(
        self, config_service: ConfigService, tmp_path: Path
    ):
        config_service.set("http.timeout.connect", 99.0)
        config_service.reset()

        save_path = tmp_path / "after_reset.yaml"
        result = config_service.save(save_path)

        assert result.success is True
        assert "all values are defaults" in save_path.read_text(encoding="utf-8")


class TestLoadGlobalSync:
    """load() must activate the parsed config into the global object."""

    @pytest.fixture
    def load_file(self, tmp_path: Path) -> Path:
        path = tmp_path / "to_load.yaml"
        path.write_text(
            "http:\n  timeout:\n    connect: 42\n",
            encoding="utf-8",
        )
        return path

    def test_load_updates_global_config(
        self, config_service: ConfigService, load_file: Path
    ):
        result = config_service.load(load_file)

        assert result.success is True
        assert get_config().http.timeout.connect == 42.0

    def test_load_preserves_identity(
        self, config_service: ConfigService, load_file: Path
    ):
        ident = id(get_config())

        result = config_service.load(load_file)

        assert result.success is True
        assert id(get_config()) == ident

    def test_load_does_not_change_config_path(
        self, config_service: ConfigService, load_file: Path
    ):
        path_before = config_service.config_path

        config_service.load(load_file)

        assert config_service.config_path == path_before
        assert config_service.config_path == get_loader().config_path

    def test_save_after_load_writes_default_path(
        self, config_service: ConfigService, load_file: Path, tmp_path: Path
    ):
        config_service.load(load_file)

        save_path = tmp_path / "saved_after_load.yaml"
        result = config_service.save(save_path)

        assert result.success is True
        assert "connect: 42" in save_path.read_text(encoding="utf-8")

    def test_load_invalid_file_warns_and_falls_back(
        self, config_service: ConfigService, tmp_path: Path
    ):
        invalid = tmp_path / "invalid.yaml"
        invalid.write_text(
            "http:\n  timeout:\n    connect: not-a-number\n",
            encoding="utf-8",
        )
        default = get_config().http.timeout.connect

        result = config_service.load(invalid)

        assert result.success is True
        assert result.warnings
        # Fallback to defaults (documented all-or-nothing behavior)
        assert get_config().http.timeout.connect == default


# =============================================================================
# Explicit mode: isolation from the global state
# =============================================================================


class TestExplicitIsolation:
    """ConfigService(config_path=...) must never touch the global state."""

    @pytest.fixture
    def explicit_service(self, tmp_path: Path) -> ConfigService:
        return ConfigService(config_path=tmp_path / "config.yaml")

    def test_explicit_service_has_own_loader(self, explicit_service: ConfigService):
        assert explicit_service.loader is not get_loader()

    def test_explicit_service_has_own_config(self, explicit_service: ConfigService):
        assert explicit_service.config is not get_config()

    def test_explicit_config_path(self, explicit_service: ConfigService, tmp_path):
        assert explicit_service.config_path == tmp_path / "config.yaml"

    def test_explicit_set_does_not_touch_global(self, explicit_service: ConfigService):
        default = get_config().http.timeout.connect

        result = explicit_service.set("http.timeout.connect", 42.0)

        assert result.success is True
        assert get_config().http.timeout.connect == default

    def test_explicit_reset_does_not_touch_global(
        self, explicit_service: ConfigService
    ):
        explicit_service.set("http.timeout.connect", 42.0)
        default = get_config().http.timeout.connect

        result = explicit_service.reset()

        assert result.success is True
        assert get_config().http.timeout.connect == default

    def test_explicit_load_does_not_touch_global(
        self, explicit_service: ConfigService, tmp_path: Path
    ):
        load_file = tmp_path / "to_load.yaml"
        load_file.write_text("http:\n  timeout:\n    connect: 42\n")
        default = get_config().http.timeout.connect

        result = explicit_service.load(load_file)

        assert result.success is True
        assert explicit_service.config.http.timeout.connect == 42.0
        assert get_config().http.timeout.connect == default

    def test_explicit_save_writes_to_explicit_path(
        self, explicit_service: ConfigService, tmp_path: Path
    ):
        explicit_service.set("http.timeout.connect", 42.0)

        result = explicit_service.save()

        assert result.success is True
        assert result.data == tmp_path / "config.yaml"
        saved = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "connect: 42" in saved


# =============================================================================
# save() behavior with the shared state
# =============================================================================


class TestSaveGlobal:
    """save() must persist runtime changes to the global loader's path."""

    def test_save_without_path_uses_global_config_path(
        self, config_service: ConfigService, tmp_path: Path, monkeypatch
    ):
        target = tmp_path / "global_config.yaml"
        monkeypatch.setattr(get_loader(), "config_path", target)
        config_service.set("http.timeout.connect", 42.0)

        result = config_service.save()

        assert result.success is True
        assert result.data == target
        assert "connect: 42" in target.read_text(encoding="utf-8")

    def test_save_does_not_change_identity(
        self, config_service: ConfigService, tmp_path: Path
    ):
        ident = id(get_config())
        config_service.set("http.timeout.connect", 42.0)

        config_service.save(tmp_path / "out.yaml")

        assert id(get_config()) == ident


# =============================================================================
# baseline_config()
# =============================================================================


class TestBaselineConfig:
    """The reset baseline must be defaults + env, without reading the file."""

    def test_baseline_is_defaults_without_file(self, tmp_path: Path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("http:\n  timeout:\n    connect: 15\n")
        loader = ConfigLoader(config_path=config_path)

        baseline = loader.baseline_config()

        assert baseline.http.timeout.connect == 10.0
        assert isinstance(baseline, AppConfig)

    def test_baseline_applies_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT", "7.5")
        loader = ConfigLoader(config_path="unused.yaml")

        baseline = loader.baseline_config()

        assert baseline.http.timeout.connect == 7.5
