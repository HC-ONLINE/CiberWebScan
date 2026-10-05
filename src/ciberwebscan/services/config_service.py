"""
Config service for CiberWebScan.

Provides configuration management functionality for CLI and API.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from ciberwebscan.config.loader import (
    Config,
    ConfigLoader,
    get_loader,
)
from ciberwebscan.services.base import (
    BaseService,
    ServiceResult,
)
from ciberwebscan.utils.path_security import (
    PathTraversalError,
    get_config_base_dir,
    validate_export_path_only,
)

logger = logging.getLogger(__name__)

# Extensions accepted for config file paths in both path policies.
ALLOWED_CONFIG_EXTENSIONS: tuple[str, ...] = (".yaml", ".yml", ".json")


class PathPolicy(str, Enum):
    """Where per-call config file paths (save/load/export) are resolved against.

    The policy only governs the ``path`` argument of ``save()``/``load()``/
    ``export_config()``. It never re-scopes an explicit ``config_path`` passed
    to the constructor (that is the caller's own pointer, see ``__init__``).
    """

    CONFIG_DIR = "config_dir"
    """Resolve paths inside ``~/.ciberwebscan`` (sandboxed, API default)."""

    LOCAL = "local"
    """Resolve paths from the current working directory (CLI policy).

    Not a sandbox: absolute paths anywhere, ``..`` and symlinks are allowed;
    only empty/null-byte input, extensions and file-type are checked.
    """


# =============================================================================
# Sensitive Field Protection
# =============================================================================

# Dot-notation paths of fields that must never be returned in plaintext via API or CLI.
_SENSITIVE_FIELDS: set[str] = {
    "api.auth.api_keys",
    "analysis.cve.nvd_api_key",
    "analysis.cve.vulners_api_key",
}

# Substrings that indicate a sensitive leaf key even if not explicitly listed above.
_SENSITIVE_SUBSTRINGS: tuple[str, ...] = ("_api_key", "_secret", "_token", "_password")


def is_sensitive_key(key: str) -> bool:
    """Return True if *key* is a dot-notation path to a sensitive config field."""
    if key in _SENSITIVE_FIELDS:
        return True
    leaf = key.rsplit(".", maxsplit=1)[-1] if "." in key else key
    return any(sub in leaf for sub in _SENSITIVE_SUBSTRINGS)


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

    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        path_policy: PathPolicy | str = PathPolicy.CONFIG_DIR,
    ):
        """
        Initialize config service.

        Args:
            config_path: Optional path to config file. If None, the service
                operates on the global configuration loader (shared with
                ``get_config()``). If given, the service uses an isolated
                private loader and never touches the global state. The path is
                normalized once (``~`` expanded, made absolute from the CWD) so
                the loader reads and ``save()`` writes exactly the same file.
                It is intentionally NOT contained to any base directory: it is
                the caller's own pointer (legacy programmatic escape hatch).
                The API must never build this service from ``request.path``.
            path_policy: Resolution policy for the ``path`` argument of
                ``save()``/``load()``/``export_config()``. A ``PathPolicy``
                member or its string value (``"config_dir"``/``"local"``);
                anything else raises ``ValueError``. Defaults to
                ``CONFIG_DIR``; the CLI passes ``LOCAL``.

        Raises:
            ValueError: If ``path_policy`` is not a valid policy. An invalid
                value never falls back to ``LOCAL`` silently.
        """
        super().__init__()

        # None => global mode (get_loader()); Path => isolated private loader.
        self._explicit_path: Path | None = (
            self._normalize_local_path(config_path) if config_path else None
        )
        # Normalize via the enum: "config_dir" must stay the sandbox even
        # though the raw value is a str, and unknown values must fail loudly
        # instead of resolving to the LOCAL branch.
        self._path_policy: PathPolicy = PathPolicy(path_policy)
        self._loader: ConfigLoader | None = None
        self._reset_mode: bool = False  # Flag to track if we're in reset mode

    @property
    def loader(self) -> ConfigLoader:
        """Get the config loader (global in default mode, private otherwise)."""
        if self._explicit_path is None:
            return get_loader()
        if self._loader is None:
            self._loader = ConfigLoader(config_path=self._explicit_path)
        return self._loader

    @property
    def config_path(self) -> Path:
        """Config file path (from the active loader)."""
        if self._explicit_path is not None:
            return self._explicit_path
        return self.loader.config_path

    @property
    def config(self) -> Config:
        """Get current configuration."""
        return self.loader.config

    def get(self, key: str) -> ServiceResult[ConfigValue]:
        """
        Get a specific configuration value.

        Sensitive values (API keys, secrets) are masked with ``'***'``.

        Args:
            key: Configuration key (dot-notation supported).

        Returns:
            ServiceResult containing ConfigValue.
        """
        result = ServiceResult[ConfigValue](success=False)

        try:
            raw_value = self._get_nested_value(self.config, key)
            default = self._get_default_value(key)
            source = self._get_value_source(key)

            result.data = ConfigValue(
                key=key,
                value=self._sanitize_value(key, raw_value),
                default=self._sanitize_value(key, default),
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

        Sensitive fields (API keys, secrets) are masked with ``'***'``.

        Returns:
            ServiceResult containing all config as dict.
        """
        result = ServiceResult[dict[str, Any]](success=False)

        try:
            config_dict = self.config.model_dump()
            result.data = self._sanitize_config_dict(config_dict)
            result.success = True

        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_ERROR"

        return result.finalize()

    def get_section(self, section: str) -> ServiceResult[dict[str, Any]]:
        """
        Get a configuration section.

        Sensitive fields (API keys, secrets) are masked with ``'***'``.

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
                section_data = section_obj.model_dump()
            else:
                section_data = dict(section_obj)

            result.data = self._sanitize_config_dict(section_data, prefix=section)
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

        The resulting configuration is validated before it is applied, so an
        invalid value never reaches the (possibly global) config object.

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

            # Validate the candidate state before mutating anything
            candidate = self.config.model_dump()
            self._set_nested_value(candidate, key, value)
            coerced = Config.model_validate(candidate)
            coerced_value = self._get_nested_value(coerced, key)

            # Update value with the validated, coerced value
            self._set_nested_value(self.config, key, coerced_value)

            # Return updated value
            result.data = ConfigValue(
                key=key,
                value=coerced_value,
                default=self._get_default_value(key),
                source="runtime",
            )
            result.success = True

            self.logger.info(
                "Configuration updated: %s = %s",
                key,
                "***" if is_sensitive_key(key) else value,
            )

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

        The reset baseline is defaults plus environment variable overrides
        (see ``ConfigLoader.baseline_config()``), so the in-memory result
        matches what a restart would produce. The config object is mutated
        in place, preserving its identity for global consumers.

        Args:
            key: Specific key to reset, or None to reset all.

        Returns:
            ServiceResult indicating success.
        """
        result = ServiceResult[bool](success=False)

        try:
            baseline = self.loader.baseline_config()

            if key:
                # Distinguish a missing key from a key whose default is None
                try:
                    default_value = self._get_nested_value(baseline, key)
                except KeyError:
                    default_value = None
                    key_exists = False
                else:
                    key_exists = True

                if key_exists:
                    self._set_nested_value(self.config, key, default_value)
                    result.data = True
                    result.success = True
                    self.logger.info(f"Reset {key} to default: {default_value}")
                else:
                    result.error = f"Key not found in defaults: {key}"
                    result.error_code = "CONFIG_KEY_NOT_FOUND"
            else:
                # Reset all - mutate the existing config object in place so
                # global consumers keep the same instance (id preserved)
                for field in Config.model_fields:
                    setattr(self.config, field, getattr(baseline, field))
                # If saving after reset, we want to create an essentially empty file
                self._reset_mode = True  # Flag to indicate we're in reset mode
                result.data = True
                result.success = True
                self.logger.info("Reset all configuration to defaults")

        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_RESET_ERROR"

        return result.finalize()

    # -------------------------------------------------------------------------
    # Path resolution
    # -------------------------------------------------------------------------

    @staticmethod
    def _normalize_local_path(value: str | Path) -> Path:
        """Normalize *value* into an absolute path resolved from the CWD.

        Used both for ``LOCAL`` policy paths and for the constructor's
        ``config_path`` (normalized exactly once so the loader and ``save()``
        always agree on the same file).

        Rejects empty paths, null bytes and Windows drive-relative paths
        (``D:file.yaml``). Expands ``~``. Relative paths become absolute from
        the current working directory; absolute paths outside the CWD are
        allowed. ``..`` and symlinks are intentionally *not* rejected: this is
        not a sandbox.

        Raises:
            ValueError: If the path is empty, contains a null byte, or is
                drive-relative on Windows.
        """
        raw = str(value)
        if not raw.strip():
            raise ValueError("Path cannot be empty")
        if "\0" in raw:
            raise ValueError("Path contains null bytes")

        expanded = Path(raw).expanduser()
        if not expanded.is_absolute() and expanded.drive:
            # Windows drive-relative ("D:file.yaml"): not anchored, reject.
            raise ValueError(f"Drive-relative path is not allowed: {raw}")
        # abspath anchors relative paths to the CWD and normalizes ". / .."
        # textually without resolving symlinks.
        return Path(os.path.abspath(expanded))

    def _resolve_user_path(
        self,
        path: str | Path,
        *,
        purpose: Literal["read", "write"],
    ) -> Path:
        """Resolve a per-call ``path`` argument according to the path policy.

        Args:
            path: Raw user-provided path (file path, not a config key).
            purpose: ``"read"`` requires an existing regular file; ``"write"``
                rejects a destination that is already a directory.

        Returns:
            The resolved absolute path.

        Raises:
            PathTraversalError: CONFIG_DIR only, if the path escapes
                ``~/.ciberwebscan``.
            ValueError: Empty path, null byte, wrong extension, drive-relative
                path (LOCAL), missing file (read) or directory destination.
            FileNotFoundError: Read path does not exist.
        """
        if self._path_policy is PathPolicy.CONFIG_DIR:
            # Expand ~ before sandboxing: "~/.ciberwebscan/x.yaml" must land
            # inside the base, "~/x.yaml" must be rejected by containment
            # instead of creating a literal "~" directory.
            expanded = os.path.expanduser(path)
            resolved = validate_export_path_only(
                expanded,
                get_config_base_dir(),
                allowed_extensions=list(ALLOWED_CONFIG_EXTENSIONS),
            )
        else:  # PathPolicy.LOCAL
            resolved = self._normalize_local_path(path)
            suffix = resolved.suffix.lower()
            if suffix not in ALLOWED_CONFIG_EXTENSIONS:
                raise ValueError(
                    f"File extension '{suffix}' not in allowed extensions: "
                    f"{list(ALLOWED_CONFIG_EXTENSIONS)}"
                )

        if purpose == "read":
            if not resolved.exists():
                raise FileNotFoundError(f"Config file not found: {resolved}")
            if not resolved.is_file():
                raise ValueError(f"Config path is not a file: {resolved}")
        elif resolved.is_dir():
            raise ValueError(f"Destination path is a directory: {resolved}")

        return resolved

    def save(self, path: str | Path | None = None) -> ServiceResult[Path]:
        """
        Save current configuration to file.

        Args:
            path: File path resolved per the configured path policy. Uses the
                service's own config path if not provided.

        Returns:
            ServiceResult containing saved file path.
        """
        result = ServiceResult[Path](success=False)

        try:
            if path is not None:
                save_path = self._resolve_user_path(path, purpose="write")
            elif self.config_path is not None:
                save_path = self.config_path
                if save_path.is_dir():
                    raise ValueError(f"Config path is a directory: {save_path}")
            else:
                save_path = Path.home() / ".ciberwebscan" / "config.yaml"

            save_path.parent.mkdir(parents=True, exist_ok=True)

            if self._reset_mode:
                # Save empty config file after reset
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write("# Configuration file - all values are defaults\n")
                self._reset_mode = False  # Clear the flag
                self.logger.info(f"Reset configuration saved to: {save_path}")
            else:
                # Normal save
                self.loader.save(save_path)

            result.data = save_path
            result.success = True

        except PathTraversalError as e:
            result.error = "Invalid configuration path"
            result.error_code = "PATH_TRAVERSAL_BLOCKED"
            self.logger.warning(f"Path traversal attempt blocked: {e}")
        except Exception as e:
            result.error = str(e)
            result.error_code = "CONFIG_SAVE_ERROR"

        return result.finalize()

    def load(self, path: str | Path) -> ServiceResult[dict[str, Any]]:
        """
        Load configuration from file.

        Sensitive fields (API keys, secrets) are masked with ``'***'``.

        Args:
            path: File path resolved per the configured path policy.

        Returns:
            ServiceResult containing loaded config with sensitive values masked.
        """
        result = ServiceResult[dict[str, Any]](success=False)

        try:
            # Raises FileNotFoundError for a missing file and ValueError for a
            # directory destination (both handled below).
            load_path = self._resolve_user_path(path, purpose="read")

            # Phase 1: parse the file with a temporary loader (never shared)
            temp_loader = ConfigLoader(config_path=load_path)
            # Access config to trigger _load() which sets validation_error
            loaded_config = temp_loader.config

            if temp_loader.validation_error is not None:
                result.warnings.append(
                    f"Invalid configuration values detected: "
                    f"{temp_loader.validation_error}. "
                    f"Falling back to default configuration."
                )
                self.logger.warning(
                    "Configuration loaded with validation errors from: %s",
                    load_path,
                )
            else:
                self.logger.info(f"Configuration loaded from: {load_path}")

            # Phase 2: activate. Global mode mutates the shared config object
            # in place (identity preserved for get_config() consumers); an
            # explicit service swaps only its private loader.
            if self._explicit_path is None:
                for field in Config.model_fields:
                    setattr(self.config, field, getattr(loaded_config, field))
            else:
                self._loader = temp_loader

            config_dict = self.config.model_dump()
            result.data = self._sanitize_config_dict(config_dict)
            result.success = True

        except PathTraversalError as e:
            result.error = "Invalid configuration path"
            result.error_code = "PATH_TRAVERSAL_BLOCKED"
            self.logger.warning(f"Path traversal attempt blocked: {e}")
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
            path: Output file path resolved per the configured path policy.
            format: Export format ('yaml', 'json').

        Returns:
            ServiceResult containing export path.
        """
        result = ServiceResult[Path](success=False)

        try:
            export_path = self._resolve_user_path(path, purpose="write")
            config_dict = self.config.model_dump()

            if format == "json":
                if self._path_policy is PathPolicy.LOCAL:
                    # LOCAL was already normalized/validated above; basing the
                    # second _export_result validation on the destination's
                    # parent keeps its mandatory-validation contract and does
                    # not add security containment (LOCAL is not a sandbox).
                    allowed_base: Path | str = export_path.parent
                else:
                    allowed_base = get_config_base_dir()
                exported, final_path = self._export_result(
                    config_dict,
                    str(export_path),
                    "json",
                    allowed_base=allowed_base,
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

        except PathTraversalError as e:
            result.error = "Invalid configuration path"
            result.error_code = "PATH_TRAVERSAL_BLOCKED"
            self.logger.warning(f"Path traversal attempt blocked: {e}")
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

    # -------------------------------------------------------------------------
    # Sensitive-field sanitization
    # -------------------------------------------------------------------------

    @staticmethod
    def _sanitize_config_dict(
        config_dict: dict[str, Any],
        prefix: str = "",
    ) -> dict[str, Any]:
        """Return a copy of *config_dict* with sensitive values replaced by ``'***'``."""
        sanitized: dict[str, Any] = {}
        for key, value in config_dict.items():
            full_path = f"{prefix}.{key}" if prefix else key

            if full_path in _SENSITIVE_FIELDS:
                if isinstance(value, list):
                    sanitized[key] = ["***"] * len(value)
                elif value is not None:
                    sanitized[key] = "***"
                else:
                    sanitized[key] = None
            elif isinstance(value, dict):
                sanitized[key] = ConfigService._sanitize_config_dict(value, full_path)
            else:
                sanitized[key] = value
        return sanitized

    @staticmethod
    def _sanitize_value(key: str, value: Any) -> Any:
        """Return ``'***'`` for sensitive values, otherwise the original value."""
        if is_sensitive_key(key):
            if isinstance(value, list):
                return ["***"] * len(value)
            if value is not None:
                return "***"
            return None
        return value
