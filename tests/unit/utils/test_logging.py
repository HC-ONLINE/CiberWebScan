"""
Tests for logging utilities.
"""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from ciberwebscan.config.models import LoggingConfig
from ciberwebscan.utils.logging import setup_logging


class TestSetupLogging:
    """Test setup_logging function."""

    def test_setup_logging_console_only(self, caplog):
        """Test logging setup with console only."""
        config = LoggingConfig(
            level="INFO",
            format="%(levelname)s - %(message)s",
            file=None,
        )

        setup_logging(config)

        # Check root logger level
        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

        # Check handlers
        assert len(root_logger.handlers) == 1
        handler = root_logger.handlers[0]
        assert isinstance(handler, logging.StreamHandler)
        assert handler.formatter._fmt == "%(levelname)s - %(message)s"

    def test_setup_logging_with_file(self, tmp_path, caplog):
        """Test logging setup with file handler."""
        log_file = tmp_path / "test.log"
        config = LoggingConfig(
            level="DEBUG",
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            file=str(log_file),
            max_size=1024,
            backup_count=2,
        )

        setup_logging(config)

        # Check root logger level
        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

        # Check handlers (console + file)
        assert len(root_logger.handlers) == 2

        # Find file handler
        file_handler = None
        console_handler = None
        for handler in root_logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                file_handler = handler
            elif isinstance(handler, logging.StreamHandler):
                console_handler = handler

        assert file_handler is not None
        assert console_handler is not None

        # Check file handler
        assert file_handler.baseFilename == str(log_file)
        assert file_handler.maxBytes == 1024
        assert file_handler.backupCount == 2
        assert (
            file_handler.formatter._fmt
            == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    def test_setup_logging_different_levels(self):
        """Test different logging levels."""
        levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }

        for level_str, level_int in levels.items():
            config = LoggingConfig(level=level_str)
            setup_logging(config)

            root_logger = logging.getLogger()
            assert root_logger.level == level_int

    def test_setup_logging_invalid_level_raises_error(self):
        """Test that invalid level raises validation error."""
        with pytest.raises(ValidationError):  # Pydantic validation error
            LoggingConfig(level="INVALID")

    def test_setup_logging_creates_file_directory(self, tmp_path):
        """Test that file directory is created if it doesn't exist."""
        log_dir = tmp_path / "subdir"
        log_file = log_dir / "app.log"

        config = LoggingConfig(
            level="INFO",
            file=str(log_file),
        )

        setup_logging(config)

        # Check directory was created
        assert log_dir.exists()
        assert log_file.exists()

    def test_setup_logging_overwrites_previous_config(self):
        """Test that setup_logging overwrites previous logging config."""
        # First config
        config1 = LoggingConfig(level="DEBUG", file=None)
        setup_logging(config1)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG
        assert len(root_logger.handlers) == 1

        # Second config
        config2 = LoggingConfig(level="ERROR", file=None)
        setup_logging(config2)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.ERROR
        assert len(root_logger.handlers) == 1

    def test_setup_logging_custom_format(self):
        """Test logging setup with custom format."""
        config = LoggingConfig(
            level="INFO",
            format="[%(levelname)s] %(message)s",
            file=None,
        )

        setup_logging(config)

        # Check formatter on console handler
        root_logger = logging.getLogger()
        console_handler = None
        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                console_handler = handler
                break

        assert console_handler is not None
        assert console_handler.formatter._fmt == "[%(levelname)s] %(message)s"
