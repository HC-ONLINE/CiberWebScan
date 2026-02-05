"""
Configuration loader for CiberWebScan.

Handles loading configuration from files (YAML, JSON), environment variables,
and merging with defaults. Provides a singleton pattern for global access.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from .defaults import DEFAULTS
from .models import (
    AppConfig as Config,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration Loader
# =============================================================================


class ConfigLoader:
    """
    Loads and manages application configuration.

    Supports:
    - YAML config files
    - JSON config files
    - Environment variable overrides
    - Default values fallback

    Example:
        loader = ConfigLoader()
        config = loader.config

        # Access values
        timeout = config.http.timeout.connect

        # Or with custom file
        loader = ConfigLoader(config_path="my_config.yaml")
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        env_prefix: str = "CIBERWEBSCAN_",
    ):
        """
        Initialize configuration loader.

        Args:
            config_path: Path to config file (YAML or JSON).
            env_prefix: Prefix for environment variable overrides.
        """
        self.config_path = Path(config_path) if config_path else None
        self.env_prefix = env_prefix
        self._config: Config | None = None
        self._raw: dict[str, Any] = {}

    @property
    def config(self) -> Config:
        """Get the loaded configuration."""
        if self._config is None:
            self._load()
        assert self._config is not None
        return self._config

    def _load(self) -> None:
        """Load configuration from all sources."""
        # Start with defaults
        self._raw = self._deep_copy(DEFAULTS)

        # Load from file if provided
        if self.config_path and self.config_path.exists():
            file_config = self._load_file(self.config_path)
            self._raw = self._deep_merge(self._raw, file_config)
            logger.debug(f"Loaded config from: {self.config_path}")

        # Apply environment overrides
        env_overrides = self._load_env()
        if env_overrides:
            self._raw = self._deep_merge(self._raw, env_overrides)
            logger.debug(f"Applied {len(env_overrides)} env overrides")

        # Parse into typed config
        try:
            self._config = Config(**self._raw)
        except PydanticValidationError as e:
            logger.error(f"Invalid configuration: {e}")
            # Fall back to defaults
            self._config = Config()

    def _load_file(self, path: Path) -> dict[str, Any]:
        """Load configuration from a file."""
        suffix = path.suffix.lower()

        try:
            with open(path, encoding="utf-8") as f:
                if suffix in (".yaml", ".yml"):
                    import yaml

                    return yaml.safe_load(f) or {}
                elif suffix == ".json":
                    import json

                    return json.load(f)
                else:
                    logger.warning(f"Unknown config format: {suffix}")
                    return {}
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            return {}

    def _load_env(self) -> dict[str, Any]:
        """Load configuration from environment variables."""
        result: dict[str, Any] = {}

        for key, value in os.environ.items():
            if not key.startswith(self.env_prefix):
                continue

            # Convert CIBERWEBSCAN_HTTP_TIMEOUT_CONNECT to http.timeout.connect
            config_key = key[len(self.env_prefix) :].lower().replace("_", ".")

            # Parse value
            parsed = self._parse_env_value(value)

            # Set nested value
            self._set_nested(result, config_key, parsed)

        return result

    def _parse_env_value(self, value: str) -> Any:
        """Parse an environment variable value."""
        # Boolean
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False

        # Number
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        # List (comma-separated)
        if "," in value:
            return [self._parse_env_value(v.strip()) for v in value.split(",")]

        return value

    def _set_nested(self, d: dict[str, Any], key: str, value: Any) -> None:
        """Set a nested dictionary value using dot notation."""
        parts = key.split(".")
        current = d

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def _deep_copy(self, d: dict) -> dict:
        """Create a deep copy of a dictionary."""
        import copy

        return copy.deepcopy(d)

    def save(self, path: str | Path) -> None:
        """
        Save current configuration to a file.

        Args:
            path: Output file path (.yaml or .json).
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        config_dict = self.config.model_dump()
        suffix = path.suffix.lower()

        with open(path, "w", encoding="utf-8") as f:
            if suffix in (".yaml", ".yml"):
                import yaml

                yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
            else:
                import json

                json.dump(config_dict, f, indent=2, default=str)

        logger.info(f"Configuration saved to: {path}")

    def reload(self) -> None:
        """Reload configuration from sources."""
        self._config = None
        self._raw = {}
        self._load()


# =============================================================================
# Global Configuration
# =============================================================================

_global_loader: ConfigLoader | None = None


def get_config() -> Config:
    """
    Get the global configuration instance.

    Returns:
        The application configuration.
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = ConfigLoader()
    return _global_loader.config


def load_config(path: str | Path | None = None) -> Config:
    """
    Load configuration from a file.

    Args:
        path: Path to config file.

    Returns:
        The loaded configuration.
    """
    global _global_loader
    _global_loader = ConfigLoader(config_path=path)
    return _global_loader.config


def reset_config() -> None:
    """Reset configuration to defaults."""
    global _global_loader
    _global_loader = None


def get_loader() -> ConfigLoader:
    """
    Get the global configuration loader.

    Returns:
        The configuration loader instance.
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = ConfigLoader()
    return _global_loader
