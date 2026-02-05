"""
Tests for ConfigService class.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ciberwebscan.services.config_service import (
    ConfigService,
    ConfigValue,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def config_service() -> ConfigService:
    """Create a test config service."""
    return ConfigService()


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """Create a test config file."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
http:
  timeout:
    connect: 15
    read: 45
scraping:
  extract_links: false
""",
        encoding="utf-8",
    )
    return config_path


# =============================================================================
# ConfigService Tests
# =============================================================================


class TestConfigService:
    """Tests for ConfigService class."""

    def test_service_creation(self, config_service: ConfigService):
        """Test service instantiation."""
        assert config_service is not None
        assert config_service.config_path is None

    def test_service_with_path(self, config_file: Path):
        """Test service with config path."""
        service = ConfigService(config_path=config_file)
        assert service.config_path == config_file

    def test_loader_property(self, config_service: ConfigService):
        """Test lazy loading of config loader."""
        loader = config_service.loader
        assert loader is not None
        # Same instance on second access
        assert loader is config_service.loader

    def test_config_property(self, config_service: ConfigService):
        """Test config property."""
        config = config_service.config
        assert config is not None


# =============================================================================
# Get Tests
# =============================================================================


class TestConfigGet:
    """Tests for configuration get operations."""

    def test_get_simple_key(self, config_service: ConfigService):
        """Test getting a simple config value."""
        result = config_service.get("http.timeout.connect")

        assert result.success is True
        assert result.data is not None
        assert result.data.key == "http.timeout.connect"
        assert result.data.value is not None

    def test_get_nonexistent_key(self, config_service: ConfigService):
        """Test getting a nonexistent key."""
        result = config_service.get("nonexistent.key.path")

        assert result.success is False
        assert result.error_code == "CONFIG_KEY_NOT_FOUND"

    def test_get_all(self, config_service: ConfigService):
        """Test getting all configuration."""
        result = config_service.get_all()

        assert result.success is True
        assert result.data is not None
        assert isinstance(result.data, dict)
        assert "http" in result.data
        assert "scraping" in result.data

    def test_get_section(self, config_service: ConfigService):
        """Test getting a configuration section."""
        result = config_service.get_section("http")

        assert result.success is True
        assert result.data is not None
        assert "timeout" in result.data

    def test_get_nonexistent_section(self, config_service: ConfigService):
        """Test getting a nonexistent section."""
        result = config_service.get_section("nonexistent")

        assert result.success is False
        assert result.error_code == "CONFIG_SECTION_NOT_FOUND"


# =============================================================================
# Set Tests
# =============================================================================


class TestConfigSet:
    """Tests for configuration set operations."""

    def test_set_value(self, config_service: ConfigService):
        """Test setting a config value."""

        result = config_service.set("http.timeout.connect", 99.0)

        assert result.success is True
        assert result.data.value == 99.0
        assert result.data.source == "runtime"

        # Verify it changed
        updated = config_service.get("http.timeout.connect")
        assert updated.data.value == 99.0

    def test_set_nonexistent_key(self, config_service: ConfigService):
        """Test setting a nonexistent key."""
        result = config_service.set("nonexistent.key", "value")

        assert result.success is False
        assert result.error_code == "CONFIG_KEY_NOT_FOUND"


# =============================================================================
# Reset Tests
# =============================================================================


class TestConfigReset:
    """Tests for configuration reset operations."""

    def test_reset_specific_key(self, config_service: ConfigService):
        """Test resetting a specific key."""
        # Change a value
        config_service.set("http.timeout.connect", 99.0)

        # Reset it
        result = config_service.reset("http.timeout.connect")

        assert result.success is True
        assert result.data is True

    def test_reset_all(self, config_service: ConfigService):
        """Test resetting all configuration."""
        # Change a value
        config_service.set("http.timeout.connect", 99.0)

        # Reset all
        result = config_service.reset()

        assert result.success is True


# =============================================================================
# Save/Load Tests
# =============================================================================


class TestConfigSaveLoad:
    """Tests for save and load operations."""

    def test_save_config(self, config_service: ConfigService, tmp_path: Path):
        """Test saving configuration."""
        save_path = tmp_path / "saved_config.yaml"

        result = config_service.save(save_path)

        assert result.success is True
        assert result.data == save_path
        assert save_path.exists()

    def test_save_config_json(self, config_service: ConfigService, tmp_path: Path):
        """Test saving configuration as JSON."""
        save_path = tmp_path / "saved_config.json"

        result = config_service.save(save_path)

        assert result.success is True
        assert save_path.exists()

    def test_load_config(self, config_file: Path):
        """Test loading configuration from file."""
        service = ConfigService()
        result = service.load(config_file)

        assert result.success is True
        assert result.data is not None

    def test_load_nonexistent_file(self, config_service: ConfigService):
        """Test loading from nonexistent file."""
        result = config_service.load("/nonexistent/config.yaml")

        assert result.success is False
        assert result.error_code == "CONFIG_FILE_NOT_FOUND"


# =============================================================================
# Export Tests
# =============================================================================


class TestConfigExport:
    """Tests for configuration export."""

    def test_export_yaml(self, config_service: ConfigService, tmp_path: Path):
        """Test exporting as YAML."""
        export_path = tmp_path / "export.yaml"

        result = config_service.export_config(export_path, format="yaml")

        assert result.success is True
        assert result.exported is True
        assert export_path.exists()

    def test_export_json(self, config_service: ConfigService, tmp_path: Path):
        """Test exporting as JSON."""
        export_path = tmp_path / "export.json"

        result = config_service.export_config(export_path, format="json")

        assert result.success is True
        assert result.exported is True


# =============================================================================
# List Keys Tests
# =============================================================================


class TestConfigListKeys:
    """Tests for listing configuration keys."""

    def test_list_all_keys(self, config_service: ConfigService):
        """Test listing all keys."""
        result = config_service.list_keys()

        assert result.success is True
        assert result.data is not None
        assert len(result.data) > 0
        assert any("http" in key for key in result.data)

    def test_list_section_keys(self, config_service: ConfigService):
        """Test listing keys in a section."""
        result = config_service.list_keys(section="http")

        assert result.success is True
        assert result.data is not None
        assert all(key.startswith("http.") for key in result.data)


# =============================================================================
# ConfigValue Tests
# =============================================================================


class TestConfigValue:
    """Tests for ConfigValue dataclass."""

    def test_config_value_creation(self):
        """Test ConfigValue creation."""
        value = ConfigValue(
            key="test.key",
            value=42,
            default=10,
            source="runtime",
            description="A test key",
        )

        assert value.key == "test.key"
        assert value.value == 42
        assert value.default == 10
        assert value.source == "runtime"
        assert value.description == "A test key"
