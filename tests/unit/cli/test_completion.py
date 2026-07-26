"""Tests for CLI completion command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from ciberwebscan.cli.app import app
from ciberwebscan.cli.commands.completion import (
    Shell,
    _detect_shell,
    _get_completion_filename,
    _get_completion_script,
    _get_install_path,
    _remove_completion_file,
    _write_completion_file,
)

runner = CliRunner()


class TestCompletionHelpers:
    """Tests for completion helper functions."""

    def test_detect_shell_returns_string(self):
        """Test _detect_shell returns a string."""
        result = _detect_shell()
        assert isinstance(result, str)

    @patch("shellingham.detect_shell")
    def test_detect_shell_with_shellingham(self, mock_detect):
        """Test _detect_shell with shellingham available."""
        mock_detect.return_value = ("zsh", "/bin/zsh")
        result = _detect_shell()
        assert result == "zsh"

    @patch("shellingham.detect_shell")
    def test_detect_shell_fallback_on_error(self, mock_detect):
        """Test _detect_shell falls back on exception."""
        mock_detect.side_effect = Exception("not found")
        result = _detect_shell()
        assert result == ""

    def test_get_completion_script_bash(self):
        """Test _get_completion_script returns bash script."""
        script = _get_completion_script(Shell.BASH)
        assert "complete" in script
        assert "ciberwebscan" in script

    def test_get_completion_script_zsh(self):
        """Test _get_completion_script returns zsh script."""
        script = _get_completion_script(Shell.ZSH)
        assert "compdef" in script
        assert "ciberwebscan" in script

    def test_get_completion_script_fish(self):
        """Test _get_completion_script returns fish script."""
        script = _get_completion_script(Shell.FISH)
        assert "complete" in script
        assert "ciberwebscan" in script

    def test_get_completion_script_unsupported(self):
        """Test _get_completion_script raises on unsupported shell."""
        import pytest

        with pytest.raises(ValueError, match="Unsupported shell"):
            _get_completion_script("powershell")

    def test_get_install_path_bash(self):
        """Test _get_install_path for bash."""
        path = _get_install_path(Shell.BASH)
        assert "bash-completion" in str(path)

    def test_get_install_path_zsh(self):
        """Test _get_install_path for zsh."""
        path = _get_install_path(Shell.ZSH)
        assert ".zsh" in str(path)

    def test_get_install_path_fish(self):
        """Test _get_install_path for fish."""
        path = _get_install_path(Shell.FISH)
        assert "fish" in str(path)

    def test_get_completion_filename_bash(self):
        """Test _get_completion_filename for bash."""
        assert _get_completion_filename(Shell.BASH) == "ciberwebscan.sh"

    def test_get_completion_filename_zsh(self):
        """Test _get_completion_filename for zsh."""
        assert _get_completion_filename(Shell.ZSH) == "_ciberwebscan"

    def test_get_completion_filename_fish(self):
        """Test _get_completion_filename for fish."""
        assert _get_completion_filename(Shell.FISH) == "ciberwebscan.fish"

    def test_write_completion_file_bash(self, tmp_path):
        """Test writing bash completion file."""
        script = _get_completion_script(Shell.BASH)
        path = _write_completion_file(Shell.BASH, script, tmp_path)
        assert path.exists()
        assert path.name == "ciberwebscan.sh"
        content = path.read_text()
        assert "complete" in content

    def test_write_completion_file_zsh(self, tmp_path):
        """Test writing zsh completion file."""
        script = _get_completion_script(Shell.ZSH)
        path = _write_completion_file(Shell.ZSH, script, tmp_path)
        assert path.exists()
        assert path.name == "_ciberwebscan"
        content = path.read_text()
        assert "compdef" in content

    def test_write_completion_file_fish(self, tmp_path):
        """Test writing fish completion file."""
        script = _get_completion_script(Shell.FISH)
        path = _write_completion_file(Shell.FISH, script, tmp_path)
        assert path.exists()
        assert path.name == "ciberwebscan.fish"
        content = path.read_text()
        assert "complete" in content

    def test_remove_completion_file_bash(self, tmp_path):
        """Test removing bash completion file."""
        script = _get_completion_script(Shell.BASH)
        _write_completion_file(Shell.BASH, script, tmp_path)
        result = _remove_completion_file(Shell.BASH, tmp_path)
        assert result is True
        assert not (tmp_path / "ciberwebscan.sh").exists()

    def test_remove_completion_file_not_found(self, tmp_path):
        """Test removing non-existent completion file."""
        result = _remove_completion_file(Shell.BASH, tmp_path)
        assert result is False


class TestCompletionCommands:
    """Tests for completion CLI commands."""

    def test_completion_help(self):
        """Test completion --help."""
        result = runner.invoke(app, ["completion", "--help"])
        assert result.exit_code == 0
        assert "completion" in result.stdout.lower()

    def test_completion_install_help(self):
        """Test completion install --help."""
        result = runner.invoke(app, ["completion", "install", "--help"])
        assert result.exit_code == 0
        assert "--shell" in result.stdout

    def test_completion_show_help(self):
        """Test completion show --help."""
        result = runner.invoke(app, ["completion", "show", "--help"])
        assert result.exit_code == 0
        assert "--shell" in result.stdout

    def test_completion_uninstall_help(self):
        """Test completion uninstall --help."""
        result = runner.invoke(app, ["completion", "uninstall", "--help"])
        assert result.exit_code == 0
        assert "--shell" in result.stdout

    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    @patch("ciberwebscan.cli.commands.completion._write_completion_file")
    def test_completion_install_auto_detect(self, mock_write, mock_detect):
        """Test completion install with auto-detected shell."""
        mock_detect.return_value = "bash"
        mock_write.return_value = Path("/tmp/ciberwebscan.sh")

        result = runner.invoke(app, ["completion", "install"])
        assert result.exit_code == 0
        mock_write.assert_called_once()

    @patch("ciberwebscan.cli.commands.completion._write_completion_file")
    def test_completion_install_explicit_shell(self, mock_write):
        """Test completion install with explicit shell."""
        mock_write.return_value = Path("/tmp/ciberwebscan.sh")

        result = runner.invoke(app, ["completion", "install", "--shell", "bash"])
        assert result.exit_code == 0
        mock_write.assert_called_once()

    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    def test_completion_install_unsupported_shell(self, mock_detect):
        """Test completion install with unsupported shell."""
        mock_detect.return_value = "powershell"

        result = runner.invoke(app, ["completion", "install"])
        assert result.exit_code == 1

    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    def test_completion_install_no_shell_detected(self, mock_detect):
        """Test completion install when shell cannot be detected."""
        mock_detect.return_value = ""

        result = runner.invoke(app, ["completion", "install"])
        assert result.exit_code == 1

    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    def test_completion_show_auto_detect(self, mock_detect):
        """Test completion show with auto-detected shell."""
        mock_detect.return_value = "bash"

        result = runner.invoke(app, ["completion", "show"])
        assert result.exit_code == 0
        assert "complete" in result.stdout

    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    def test_completion_uninstall_auto_detect(self, mock_detect):
        """Test completion uninstall with auto-detected shell."""
        mock_detect.return_value = "bash"

        result = runner.invoke(app, ["completion", "uninstall"])
        assert result.exit_code == 0

    @patch("ciberwebscan.cli.commands.completion._remove_completion_file")
    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    def test_completion_uninstall_removes_file(self, mock_detect, mock_remove):
        """Test completion uninstall removes file."""
        mock_detect.return_value = "bash"
        mock_remove.return_value = True

        result = runner.invoke(app, ["completion", "uninstall"])
        assert result.exit_code == 0
        mock_remove.assert_called_once()

    @patch("ciberwebscan.cli.commands.completion._remove_completion_file")
    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    def test_completion_uninstall_not_found(self, mock_detect, mock_remove):
        """Test completion uninstall when no file found."""
        mock_detect.return_value = "bash"
        mock_remove.return_value = False

        result = runner.invoke(app, ["completion", "uninstall"])
        assert result.exit_code == 0


class TestCompletionPermissionError:
    """Tests for permission error handling."""

    @patch("ciberwebscan.cli.commands.completion._detect_shell")
    @patch("ciberwebscan.cli.commands.completion._write_completion_file")
    def test_completion_install_permission_error(self, mock_write, mock_detect):
        """Test completion install handles PermissionError."""
        mock_detect.return_value = "bash"
        mock_write.side_effect = PermissionError("denied")

        result = runner.invoke(app, ["completion", "install"])
        assert result.exit_code == 1
