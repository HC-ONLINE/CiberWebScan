"""
Integration tests for logging configuration in CLI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_LOG_FORMAT = "%(levelname)s - %(name)s - %(message)s"


@pytest.mark.slow
class TestLoggingIntegration:
    """Integration tests for logging in CLI context."""

    def test_cli_uses_configured_logging_level(self, tmp_path):
        """Test that CLI respects logging level from config."""
        env = os.environ.copy()
        env["CIBERWEBSCAN_LOGGING_LEVEL"] = "DEBUG"
        env["CIBERWEBSCAN_LOGGING_FORMAT"] = _LOG_FORMAT

        result = subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
            env=env,
        )

        # Check that DEBUG logs appear in stderr
        assert "DEBUG" in result.stderr
        assert "ciberwebscan.config.loader" in result.stderr

    def test_cli_logs_to_file_when_configured(self, tmp_path):
        """Test that CLI logs to file when configured."""
        log_file = tmp_path / "cli.log"

        env = os.environ.copy()
        env["CIBERWEBSCAN_LOGGING_FILE"] = str(log_file)
        env["CIBERWEBSCAN_LOGGING_FORMAT"] = _LOG_FORMAT

        subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
            env=env,
        )

        # Check that log file was created and contains logs
        assert log_file.exists()
        log_content = log_file.read_text()
        assert "INFO" in log_content or "DEBUG" in log_content

    def test_cli_respects_log_level_filtering(self, tmp_path):
        """Test that CLI filters logs based on level."""
        env = os.environ.copy()
        env["CIBERWEBSCAN_LOGGING_LEVEL"] = "WARNING"
        env["CIBERWEBSCAN_LOGGING_FORMAT"] = _LOG_FORMAT

        result = subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
            env=env,
        )

        # Should not contain DEBUG logs
        assert "DEBUG" not in result.stderr

        env["CIBERWEBSCAN_LOGGING_LEVEL"] = "DEBUG"

        result_debug = subprocess.run(
            [sys.executable, "-m", "ciberwebscan", "config", "show"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent.parent,
            env=env,
        )

        # Should contain DEBUG logs
        assert "DEBUG" in result_debug.stderr
