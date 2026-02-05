"""
Config service for CiberWebScan.

Provides configuration management functionality for CLI and API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ciberwebscan.config.loader import (
    Config,
    ConfigLoader,
    reset_config,
)
from ciberwebscan.services.base import (
    BaseService,
    ServiceResult,
)

logger = logging.getLogger(__name__)


@dataclass
class ConfigValue:
    """Represents a configuration value with metadata."""

    key: str
    value: Any
    default: Any
    source: str  # 'file', 'env', 'default', 'runtime'
    description: str = ""


class ConfigService(BaseService):
    """
    Service for configuration management.

    Provides high-level interface for:
    - Viewing current configuration
    - Updating configuration values
    - Resetting to defaults
    - Exporting/importing configuration

    Example:
        service = ConfigService()

        # Get all config
        result = service.get_all()
        for key, value in result.data.items():
            print(f"{key}: {value}")

        # Set a value
        service.set("scraping.timeout", 60)

        # Reset to defaults
        service.reset()
    """

    def __init__(self, config_path: str | Path | None = None):
        """
        Initialize config service.

        Args:
            config_path: Optional path to config file.
        """
        super().__init__()
        self.config_path = Path(config_path) if config_path else None
        self._loader: ConfigLoader | None = None

    @property
    def loader(self) -> ConfigLoader:
        """Get or create config loader."""
        if self._loader is None:
            self._loader = ConfigLoader(config_path=self.config_path)
        return self._loader

    @property
    def config(self) -> Config:
        """Get current configuration."""
        return self.loader.config

    def get(self, key: str) -> ServiceResult[ConfigValue]:
        """
        Get a specific configuration value.

        Args:
            key: Configuration key (dot-notation supported).

        Returns:
            ServiceResult containing ConfigValue.
        """
        result = ServiceResult[ConfigValue](success=False)

        try:
            value = self._get_nested_value(self.config, key)
            default = self._get_default_value(key)
            source = self._get_value_source(key)

            result.data = ConfigValue(
                key=key,
                value=value,
                default=default,
                source=source,
            )
            result.success = True

        except KeyError:
            result.error = f"Configuration key not found: {key}"
            result.error_code = "CONFIG_KEY_NOT_FOUND"
        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_ERROR"

        return result.finalize()

    def get_all(self) -> ServiceResult[dict[str, Any]]:
        """
        Get all configuration values.

        Returns:
            ServiceResult containing all config as dict.
        """
        result = ServiceResult[dict[str, Any]](success=False)

        try:
            config_dict = self.config.model_dump()
            result.data = config_dict
            result.success = True

        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_ERROR"

        return result.finalize()

    def get_section(self, section: str) -> ServiceResult[dict[str, Any]]:
        """
        Get a configuration section.

        Args:
            section: Section name (e.g., 'scraping', 'analysis').

        Returns:
            ServiceResult containing section config.
        """
        result = ServiceResult[dict[str, Any]](success=False)

        try:
            section_obj = getattr(self.config, section, None)
            if section_obj is None:
                raise KeyError(f"Section not found: {section}")

            if hasattr(section_obj, "model_dump"):
                result.data = section_obj.model_dump()
            else:
                result.data = dict(section_obj)

            result.success = True

        except KeyError as e:
            result.error = str(e)
            result.error_code = "CONFIG_SECTION_NOT_FOUND"
        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_ERROR"

        return result.finalize()

    def set(self, key: str, value: Any) -> ServiceResult[ConfigValue]:
        """
        Set a configuration value.

        Args:
            key: Configuration key (dot-notation supported).
            value: New value.

        Returns:
            ServiceResult containing updated ConfigValue.
        """
        result = ServiceResult[ConfigValue](success=False)

        try:
            # Validate key exists
            _ = self._get_nested_value(self.config, key)

            # Update value
            self._set_nested_value(self.config, key, value)

            # Return updated value
            result.data = ConfigValue(
                key=key,
                value=value,
                default=self._get_default_value(key),
                source="runtime",
            )
            result.success = True

            self.logger.info(f"Configuration updated: {key} = {value}")

        except KeyError:
            result.error = f"Configuration key not found: {key}"
            result.error_code = "CONFIG_KEY_NOT_FOUND"
        except ValueError as e:
            result.error = f"Invalid value: {e}"
            result.error_code = "CONFIG_INVALID_VALUE"
        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_ERROR"

        return result.finalize()

    def reset(self, key: str | None = None) -> ServiceResult[bool]:
        """
        Reset configuration to defaults.

        Args:
            key: Specific key to reset, or None for all.

        Returns:
            ServiceResult indicating success.
        """
        result = ServiceResult[bool](success=False)

        try:
            if key:
                default = self._get_default_value(key)
                self._set_nested_value(self.config, key, default)
                self.logger.info(f"Configuration reset: {key}")
            else:
                reset_config()
                self._loader = None  # Force reload
                self.logger.info("All configuration reset to defaults")

            result.data = True
            result.success = True

        except KeyError:
            result.error = f"Configuration key not found: {key}"
            result.error_code = "CONFIG_KEY_NOT_FOUND"
        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_ERROR"

        return result.finalize()

    def save(self, path: str | Path | None = None) -> ServiceResult[Path]:
        """
        Save current configuration to file.

        Args:
            path: File path. Uses default if not provided.

        Returns:
            ServiceResult containing saved file path.
        """
        result = ServiceResult[Path](success=False)

        try:
            save_path = Path(path) if path else self.config_path
            if save_path is None:
                save_path = Path.home() / ".ciberwebscan" / "config.yaml"

            save_path.parent.mkdir(parents=True, exist_ok=True)
            self.loader.save(save_path)

            result.data = save_path
            result.success = True
            self.logger.info(f"Configuration saved to: {save_path}")

        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_SAVE_ERROR"

        return result.finalize()

    def load(self, path: str | Path) -> ServiceResult[dict[str, Any]]:
        """
        Load configuration from file.

        Args:
            path: File path to load.

        Returns:
            ServiceResult containing loaded config.
        """
        result = ServiceResult[dict[str, Any]](success=False)

        try:
            load_path = Path(path)
            if not load_path.exists():
                raise FileNotFoundError(f"Config file not found: {load_path}")

            self._loader = ConfigLoader(config_path=load_path)
            result.data = self.config.model_dump()
            result.success = True
            self.logger.info(f"Configuration loaded from: {load_path}")

        except FileNotFoundError as e:
            result.error = str(e)
            result.error_code = "CONFIG_FILE_NOT_FOUND"
        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_LOAD_ERROR"

        return result.finalize()

    def export_config(
        self,
        path: str | Path,
        format: str = "yaml",
    ) -> ServiceResult[Path]:
        """
        Export configuration to file.

        Args:
            path: Output file path.
            format: Export format ('yaml', 'json').

        Returns:
            ServiceResult containing export path.
        """
        result = ServiceResult[Path](success=False)

        try:
            export_path = Path(path)
            config_dict = self.config.model_dump()

            if format == "json":
                exported, final_path = self._export_result(
                    config_dict,
                    str(export_path),
                    "json",
                )
            else:
                # YAML export
                import yaml

                export_path.parent.mkdir(parents=True, exist_ok=True)
                with open(export_path, "w", encoding="utf-8") as f:
                    yaml.dump(config_dict, f, default_flow_style=False)
                final_path = export_path

            result.data = final_path
            result.success = True
            result.exported = True
            result.export_path = final_path
            result.export_format = format

        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_EXPORT_ERROR"

        return result.finalize()

    def list_keys(self, section: str | None = None) -> ServiceResult[list[str]]:
        """
        List all configuration keys.

        Args:
            section: Optional section filter.

        Returns:
            ServiceResult containing list of keys.
        """
        result = ServiceResult[list[str]](success=False)

        try:
            if section:
                section_obj = getattr(self.config, section, None)
                if section_obj is None:
                    raise KeyError(f"Section not found: {section}")
                keys = self._get_all_keys(section_obj, prefix=section)
            else:
                keys = self._get_all_keys(self.config)

            result.data = keys
            result.success = True

        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_ERROR"

        return result.finalize()

    def _get_nested_value(self, obj: Any, key: str) -> Any:
        """Get nested value using dot notation."""
        parts = key.split(".")
        current = obj

        for part in parts:
            if hasattr(current, part):
                current = getattr(current, part)
            elif isinstance(current, dict) and part in current:
                current = current[part]
            else:
                raise KeyError(f"Key not found: {part}")

        return current

    def _set_nested_value(self, obj: Any, key: str, value: Any) -> None:
        """Set nested value using dot notation."""
        parts = key.split(".")
        current = obj

        for part in parts[:-1]:
            if hasattr(current, part):
                current = getattr(current, part)
            elif isinstance(current, dict):
                current = current[part]
            else:
                raise KeyError(f"Key not found: {part}")

        final_key = parts[-1]
        if hasattr(current, final_key):
            setattr(current, final_key, value)
        elif isinstance(current, dict):
            current[final_key] = value
        else:
            raise KeyError(f"Cannot set key: {final_key}")

    def _get_default_value(self, key: str) -> Any:
        """Get default value for a key."""
        from ciberwebscan.config.loader import Config

        defaults = Config()
        try:
            return self._get_nested_value(defaults, key)
        except KeyError:
            return None

    def _get_value_source(self, key: str) -> str:
        """Determine source of a config value."""
        # This is simplified - in a full implementation would track sources
        default = self._get_default_value(key)
        current = self._get_nested_value(self.config, key)

        if current == default:
            return "default"
        elif self.config_path and self.config_path.exists():
            return "file"
        else:
            return "runtime"

    def _get_all_keys(self, obj: Any, prefix: str = "") -> list[str]:
        """Recursively get all configuration keys."""
        keys: list[str] = []

        if hasattr(obj, "model_dump"):
            data = obj.model_dump()
        elif isinstance(obj, dict):
            data = obj
        else:
            return [prefix] if prefix else []

        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k

            if isinstance(v, dict):
                keys.extend(self._get_all_keys(v, full_key))
            else:
                keys.append(full_key)

        return keys
