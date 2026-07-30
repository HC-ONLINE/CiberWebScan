"""Tests for CLI app and commands."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from ciberwebscan.cli.app import app

runner = CliRunner()


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class TestAppBasic:
    """Tests for basic CLI app functionality."""

    def test_help(self):
        """Test --help flag."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "CiberWebScan" in result.stdout

    def test_version(self):
        """Test version command."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "CiberWebScan" in result.stdout

    def test_no_args_shows_help(self):
        """Test no arguments shows help."""
        result = runner.invoke(app, [])
        assert "Usage" in result.stdout


class TestScrapeCommand:
    """Tests for scrape command."""

    def test_scrape_help(self):
        """Test scrape --help."""
        result = runner.invoke(app, ["scrape", "--help"])
        assert result.exit_code == 0
        assert "scrape" in result.stdout.lower()

    def test_scrape_url_help(self):
        """Test scrape url --help."""
        result = runner.invoke(app, ["scrape", "url", "--help"])
        assert result.exit_code == 0
        assert "URL" in result.stdout

    @patch("ciberwebscan.services.ScrapeService")
    @patch("ciberwebscan.services.ScrapeOptions")
    def test_scrape_url_success(self, mock_options_class, mock_service_class):
        """Test successful scrape."""
        # Setup mock
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        # Use spec=[] to prevent MagicMock creating auto attributes
        mock_result.data = MagicMock(
            url="https://example.com",
            status_code=200,
            title="Test",
            text_content=None,
            elapsed_ms=None,
        )
        mock_result.duration_seconds = 0.5
        mock_result.exported = False
        mock_service.scrape.return_value = mock_result
        mock_service_class.return_value = mock_service

        result = runner.invoke(app, ["scrape", "url", "https://example.com", "-q"])
        # Should complete without error
        assert result.exit_code == 0

    def test_scrape_url_invalid(self):
        """Test scrape with invalid URL."""
        result = runner.invoke(app, ["scrape", "url", ""])
        assert result.exit_code == 2
        assert "error" in result.stdout.lower() or result.exit_code != 0

    def test_scrape_batch_help(self):
        """Test scrape batch --help."""
        result = runner.invoke(app, ["scrape", "batch", "--help"])
        assert result.exit_code == 0


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_help(self):
        """Test analyze --help."""
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "analyze" in result.stdout.lower()

    def test_analyze_ssl_flag(self):
        """Test analyze --ssl flag is available."""
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--ssl" in _strip_ansi(result.stdout).lower()

    def test_analyze_fingerprint_flag(self):
        """Test analyze --fingerprint flag is available."""
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--fingerprint" in _strip_ansi(result.stdout).lower()

    @patch("ciberwebscan.services.AnalyzeService")
    def test_analyze_url_success(self, mock_service_class):
        """Test successful analyze."""
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.data = MagicMock()
        mock_result.data.meta = MagicMock(
            target_url="https://example.com", timestamp=None
        )
        mock_result.data.ssl = None
        mock_result.data.fingerprint = None
        mock_result.data.cves = []
        mock_result.duration_seconds = 1.0
        mock_result.exported = False
        mock_service.analyze.return_value = mock_result
        mock_service_class.return_value = mock_service

        result = runner.invoke(app, ["analyze", "https://example.com", "--ssl", "-q"])
        assert result.exit_code == 0


class TestConfigCommand:
    """Tests for config command."""

    def test_config_help(self):
        """Test config --help."""
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0
        assert "config" in result.stdout.lower()

    def test_config_show_help(self):
        """Test config show --help."""
        result = runner.invoke(app, ["config", "show", "--help"])
        assert result.exit_code == 0

    def test_config_get_help(self):
        """Test config get --help."""
        result = runner.invoke(app, ["config", "get", "--help"])
        assert result.exit_code == 0

    def test_config_set_help(self):
        """Test config set --help."""
        result = runner.invoke(app, ["config", "set", "--help"])
        assert result.exit_code == 0

    def test_config_reset_help(self):
        """Test config reset --help."""
        result = runner.invoke(app, ["config", "reset", "--help"])
        assert result.exit_code == 0

    def test_config_keys_help(self):
        """Test config keys --help."""
        result = runner.invoke(app, ["config", "keys", "--help"])
        assert result.exit_code == 0

    @patch("ciberwebscan.services.ConfigService")
    def test_config_show_success(self, mock_service_class):
        """Test successful config show."""
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.data = {"http": {"timeout": 30}, "scraping": {"max_pages": 10}}
        mock_result.duration_seconds = 0.01
        mock_result.exported = False
        mock_service.get_all.return_value = mock_result
        mock_service_class.return_value = mock_service

        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0


class TestQuickCommand:
    """Tests for quick command."""

    def test_quick_help(self):
        """Test quick --help."""
        result = runner.invoke(app, ["quick", "--help"])
        assert result.exit_code == 0
        assert "quick" in result.stdout.lower()
