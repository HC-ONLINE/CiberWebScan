"""
Path security utilities for CiberWebScan.

Provides centralized path validation to prevent path traversal attacks.
All filesystem operations that accept user-controlled paths should use
these utilities to ensure paths remain within allowed directories.
"""

from __future__ import annotations

import os
from pathlib import Path


class PathTraversalError(Exception):
    """Raised when a path attempts to escape the allowed directory."""

    def __init__(self, path: str, allowed_dir: str) -> None:
        self.path = path
        self.allowed_dir = allowed_dir
        super().__init__(
            f"Path traversal detected: '{path}' escapes allowed directory '{allowed_dir}'"
        )


def resolve_and_validate_path(
    user_path: str | Path,
    allowed_base: str | Path,
) -> Path:
    """
    Resolve a user-provided path and ensure it stays within the allowed base directory.

    This function defends against:
    - Relative traversal sequences (../, ..\\)
    - Absolute paths that escape the base
    - Symlink-based escapes (resolved paths are validated)
    - Null bytes and other path injection attempts
    - Cross-platform path manipulation (Windows and POSIX)

    Note on symlinks: ``Path.resolve()`` follows symlinks, so the resolved
    real path is what gets validated against the base directory. This means
    a symlink ``allowed/link -> outside/file`` will be correctly rejected
    because the resolved path lands outside the base. If you need to
    *reject* symlinks entirely (not follow them), use ``Path.is_symlink()``
    separately before calling this function.

    Args:
        user_path: The path provided by the user.
        allowed_base: The directory the path must remain within.

    Returns:
        Resolved Path object within the allowed base.

    Raises:
        PathTraversalError: If the path escapes the allowed directory.
        ValueError: If the path is empty or contains null bytes.
    """
    if not user_path:
        raise ValueError("Path cannot be empty")

    user_str = str(user_path)

    # Block null byte injection
    if "\0" in user_str:
        raise ValueError("Path contains null bytes")

    base = Path(allowed_base).resolve()

    # Convert to Path and resolve parent components only
    # This normalizes ../ and ./ sequences without following symlinks on the final component
    candidate = Path(user_str)

    # If the user path is absolute, it must be within the base
    if candidate.is_absolute():
        # On Windows, check drive letter too
        resolved = candidate.resolve()
        if not _is_within_directory(resolved, base):
            raise PathTraversalError(user_str, str(base))
        return resolved

    # For relative paths, resolve against the base
    # First, resolve parent to handle ../ correctly
    # We use base / candidate and then resolve the whole thing
    resolved = (base / candidate).resolve()

    if not _is_within_directory(resolved, base):
        raise PathTraversalError(user_str, str(base))

    return resolved


def _is_within_directory(path: Path, directory: Path) -> bool:
    """
    Check if a resolved path is within the specified directory.

    Uses os.path.commonpath for reliable cross-platform comparison.
    """
    try:
        # Resolve both to absolute paths
        path_abs = path.resolve()
        dir_abs = directory.resolve()

        # Use commonpath to find the common ancestor
        common = Path(os.path.commonpath([str(path_abs), str(dir_abs)]))

        # The path is within the directory if the common ancestor is the directory itself
        return common == dir_abs
    except (ValueError, OSError):
        # On Windows, commonpath raises ValueError if paths are on different drives
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing directory separators and dangerous characters.

    This is a secondary defense - the primary defense should always be
    resolve_and_validate_path().

    Args:
        filename: The filename to sanitize.

    Returns:
        Sanitized filename safe for use in the allowed directory.

    Raises:
        ValueError: If the filename is empty after sanitization.
    """
    if not filename:
        raise ValueError("Filename cannot be empty")

    # Remove any path separators
    sanitized = filename.replace("/", "").replace("\\", "")

    # Remove null bytes
    sanitized = sanitized.replace("\0", "")

    # Remove leading dots to prevent hidden files and .. sequences
    sanitized = sanitized.lstrip(".")

    # If nothing left, raise
    if not sanitized:
        raise ValueError("Filename is empty after sanitization")

    return sanitized


def validate_export_path(
    user_path: str | Path,
    allowed_base: str | Path,
    *,
    allow_overwrite: bool = True,
    allowed_extensions: list[str] | None = None,
) -> Path:
    """
    Validate an export path for writing files.

    Extends resolve_and_validate_path with additional write-specific checks.

    Args:
        user_path: The path provided by the user.
        allowed_base: The directory the path must remain within.
        allow_overwrite: If False, raise if the file already exists.
        allowed_extensions: Optional list of allowed file extensions (e.g., ['.yaml', '.json']).

    Returns:
        Resolved and validated Path object.

    Raises:
        PathTraversalError: If the path escapes the allowed directory.
        ValueError: If validation fails for other reasons.
    """
    resolved = validate_export_path_only(
        user_path,
        allowed_base,
        allowed_extensions=allowed_extensions,
    )

    if not allow_overwrite and resolved.exists():
        raise ValueError(f"File already exists: {resolved}")

    return resolved


def validate_export_path_only(
    user_path: str | Path,
    allowed_base: str | Path,
    *,
    allowed_extensions: list[str] | None = None,
) -> Path:
    """
    Validate an export path without checking file existence.

    Args:
        user_path: The path provided by the user.
        allowed_base: The directory the path must remain within.
        allowed_extensions: Optional list of allowed file extensions.

    Returns:
        Resolved and validated Path object.

    Raises:
        PathTraversalError: If the path escapes the allowed directory.
        ValueError: If validation fails for other reasons.
    """
    resolved = resolve_and_validate_path(user_path, allowed_base)

    if allowed_extensions:
        suffix = resolved.suffix.lower()
        if suffix not in allowed_extensions:
            raise ValueError(
                f"File extension '{suffix}' not in allowed extensions: {allowed_extensions}"
            )

    return resolved


def get_config_base_dir() -> Path:
    """
    Get the base directory for configuration file operations.

    Returns the user's home .ciberwebscan directory, creating it if needed.

    Returns:
        Path to the configuration base directory.
    """
    base = Path.home() / ".ciberwebscan"
    base.mkdir(parents=True, exist_ok=True)
    return base.resolve()


def get_export_base_dir() -> Path:
    """
    Get the base directory for export file operations.

    Returns the exports directory within the project or user's home.

    Returns:
        Path to the export base directory.
    """
    # Check if we're in a project directory with exports/
    cwd = Path.cwd()
    project_exports = cwd / "exports"
    if project_exports.exists() or (cwd / "pyproject.toml").exists():
        project_exports.mkdir(parents=True, exist_ok=True)
        return project_exports.resolve()

    # Fallback to user's home
    home_exports = Path.home() / ".ciberwebscan" / "exports"
    home_exports.mkdir(parents=True, exist_ok=True)
    return home_exports.resolve()
