"""
Security tests for path traversal prevention.

These tests verify that the path security utilities correctly prevent
path traversal attacks across different operating systems and attack vectors.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ciberwebscan.utils.path_security import (
    PathTraversalError,
    get_config_base_dir,
    get_export_base_dir,
    resolve_and_validate_path,
    sanitize_filename,
    validate_export_path,
)


class TestResolveAndValidatePath:
    """Tests for the core path validation function."""

    def test_relative_path_within_base(self, tmp_path: Path) -> None:
        """Relative paths within the base directory should be allowed."""
        (tmp_path / "config.yaml").write_text("test: true")
        result = resolve_and_validate_path("config.yaml", tmp_path)
        assert result == tmp_path / "config.yaml"

    def test_relative_subdirectory_within_base(self, tmp_path: Path) -> None:
        """Relative paths in subdirectories within base should be allowed."""
        sub = tmp_path / "profiles"
        sub.mkdir()
        (sub / "test.yaml").write_text("test: true")
        result = resolve_and_validate_path("profiles/test.yaml", tmp_path)
        assert result == sub / "test.yaml"

    def test_absolute_path_within_base(self, tmp_path: Path) -> None:
        """Absolute paths within the base directory should be allowed."""
        (tmp_path / "config.yaml").write_text("test: true")
        result = resolve_and_validate_path(str(tmp_path / "config.yaml"), tmp_path)
        assert result == tmp_path / "config.yaml"

    def test_traversal_with_dotslash(self, tmp_path: Path) -> None:
        """Paths with ./ should be resolved and validated."""
        (tmp_path / "config.yaml").write_text("test: true")
        result = resolve_and_validate_path("./config.yaml", tmp_path)
        assert result == tmp_path / "config.yaml"

    def test_traversal_with_single_dotdot(self, tmp_path: Path) -> None:
        """Paths attempting single ../ traversal should be rejected."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.yaml").write_text("secret: true")
        with pytest.raises(PathTraversalError):
            resolve_and_validate_path("../outside/secret.yaml", tmp_path)

    def test_traversal_with_multiple_dotdot(self, tmp_path: Path) -> None:
        """Paths attempting multiple ../../ traversal should be rejected."""
        with pytest.raises(PathTraversalError):
            resolve_and_validate_path("../../../etc/passwd", tmp_path)

    def test_traversal_absolute_path_outside(self, tmp_path: Path) -> None:
        """Absolute paths outside the base should be rejected."""
        with pytest.raises(PathTraversalError):
            resolve_and_validate_path("/etc/passwd", tmp_path)

    def test_nested_traversal(self, tmp_path: Path) -> None:
        """Nested traversal attempts like foo/../../bar should be rejected."""
        (tmp_path / "foo").mkdir()
        with pytest.raises(PathTraversalError):
            resolve_and_validate_path("foo/../../secret.yaml", tmp_path)

    def test_empty_path_rejected(self, tmp_path: Path) -> None:
        """Empty paths should be rejected."""
        with pytest.raises(ValueError, match="Path cannot be empty"):
            resolve_and_validate_path("", tmp_path)

    def test_null_byte_rejected(self, tmp_path: Path) -> None:
        """Paths with null bytes should be rejected."""
        with pytest.raises(ValueError, match="null bytes"):
            resolve_and_validate_path("config.yaml\0/etc/passwd", tmp_path)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_absolute_path(self, tmp_path: Path) -> None:
        """Windows absolute paths outside base should be rejected."""
        with pytest.raises(PathTraversalError):
            resolve_and_validate_path("C:\\Windows\\System32\\config\\SAM", tmp_path)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_universal_naming_convention(self, tmp_path: Path) -> None:
        """Windows forward slash paths outside base should be rejected."""
        with pytest.raises(PathTraversalError):
            resolve_and_validate_path("C:/Windows/System32/config/SAM", tmp_path)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows requires special privileges for symlink creation",
    )
    def test_symlink_within_base(self, tmp_path: Path) -> None:
        """Symlinks that resolve within base should be allowed."""
        target = tmp_path / "target.yaml"
        target.write_text("test: true")
        link = tmp_path / "link.yaml"
        link.symlink_to(target)
        result = resolve_and_validate_path("link.yaml", tmp_path)
        assert result == link.resolve()

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows requires special privileges for symlink creation",
    )
    def test_symlink_outside_base(self, tmp_path: Path) -> None:
        """Symlinks that resolve outside base should be rejected."""
        # Create target OUTSIDE the base directory
        outside = tmp_path.parent / "symlink_outside_target"
        outside.mkdir(exist_ok=True)
        try:
            target = outside / "secret.yaml"
            target.write_text("secret: true")
            link = tmp_path / "link.yaml"
            link.symlink_to(target)
            with pytest.raises(PathTraversalError):
                resolve_and_validate_path("link.yaml", tmp_path)
        finally:
            import shutil

            shutil.rmtree(outside, ignore_errors=True)


class TestValidateExportPath:
    """Tests for export path validation."""

    def test_valid_export_path(self, tmp_path: Path) -> None:
        """Valid export paths within base should be allowed."""
        result = validate_export_path("output.json", tmp_path)
        assert result == tmp_path / "output.json"

    def test_export_with_extension_check(self, tmp_path: Path) -> None:
        """Export paths with valid extensions should be allowed."""
        result = validate_export_path(
            "config.yaml", tmp_path, allowed_extensions=[".yaml", ".json"]
        )
        assert result == tmp_path / "config.yaml"

    def test_export_with_invalid_extension(self, tmp_path: Path) -> None:
        """Export paths with invalid extensions should be rejected."""
        with pytest.raises(ValueError, match="not in allowed extensions"):
            validate_export_path(
                "script.py", tmp_path, allowed_extensions=[".yaml", ".json"]
            )

    def test_export_traversal_rejected(self, tmp_path: Path) -> None:
        """Export paths with traversal should be rejected."""
        with pytest.raises(PathTraversalError):
            validate_export_path("../../etc/cron.d/backdoor", tmp_path)


class TestSanitizeFilename:
    """Tests for filename sanitization."""

    def test_normal_filename(self) -> None:
        """Normal filenames should pass through."""
        assert sanitize_filename("config.yaml") == "config.yaml"

    def test_filename_with_slashes(self) -> None:
        """Filenames with slashes should have them removed."""
        assert sanitize_filename("path/to/file.yaml") == "pathtofile.yaml"

    def test_filename_with_backslashes(self) -> None:
        """Filenames with backslashes should have them removed."""
        assert sanitize_filename("path\\to\\file.yaml") == "pathtofile.yaml"

    def test_filename_with_dots(self) -> None:
        """Filenames starting with dots should have leading dots removed."""
        assert sanitize_filename("...hidden") == "hidden"

    def test_empty_after_sanitize(self) -> None:
        """Filenames that become empty after sanitization should raise."""
        with pytest.raises(ValueError, match="empty after sanitization"):
            sanitize_filename("...")

    def test_null_bytes_removed(self) -> None:
        """Null bytes should be removed."""
        assert sanitize_filename("file\0name.yaml") == "filename.yaml"


class TestConfigBaseDir:
    """Tests for config base directory."""

    def test_returns_path(self) -> None:
        """Should return a Path object."""
        result = get_config_base_dir()
        assert isinstance(result, Path)

    def test_returns_absolute(self) -> None:
        """Should return an absolute path."""
        result = get_config_base_dir()
        assert result.is_absolute()

    def test_is_ciberwebscan_dir(self) -> None:
        """Should point to .ciberwebscan directory."""
        result = get_config_base_dir()
        assert result.name == ".ciberwebscan"


class TestExportBaseDir:
    """Tests for export base directory."""

    def test_returns_path(self) -> None:
        """Should return a Path object."""
        result = get_export_base_dir()
        assert isinstance(result, Path)

    def test_returns_absolute(self) -> None:
        """Should return an absolute path."""
        result = get_export_base_dir()
        assert result.is_absolute()


class TestConfigServicePathSecurity:
    """Integration tests for ConfigService path security."""

    def test_load_traversal_rejected(self, tmp_path: Path) -> None:
        """ConfigService.load should reject traversal paths."""
        from ciberwebscan.services.config_service import ConfigService

        service = ConfigService()
        result = service.load("../../../etc/passwd")
        assert not result.success
        assert result.error_code == "PATH_TRAVERSAL_BLOCKED"

    def test_export_traversal_rejected(self, tmp_path: Path) -> None:
        """ConfigService.export_config should reject traversal paths."""
        from ciberwebscan.services.config_service import ConfigService

        service = ConfigService()
        result = service.export_config("../../etc/cron.d/backdoor")
        assert not result.success
        assert result.error_code == "PATH_TRAVERSAL_BLOCKED"

    def test_save_traversal_rejected(self, tmp_path: Path) -> None:
        """ConfigService.save should reject traversal paths."""
        from ciberwebscan.services.config_service import ConfigService

        service = ConfigService()
        result = service.save("../../../tmp/evil.yaml")
        assert not result.success
        assert result.error_code == "PATH_TRAVERSAL_BLOCKED"

    def test_load_within_config_dir_allowed(self, tmp_path: Path) -> None:
        """ConfigService.load should allow paths within config directory."""
        from unittest.mock import patch

        from ciberwebscan.services.config_service import ConfigService

        config_dir = tmp_path / ".ciberwebscan"
        config_dir.mkdir()
        config_file = config_dir / "test.yaml"
        config_file.write_text("http:\n  timeout:\n    connect: 10\n")

        with patch(
            "ciberwebscan.services.config_service.get_config_base_dir",
            return_value=config_dir,
        ):
            service = ConfigService()
            result = service.load(config_file)
            assert result.success
