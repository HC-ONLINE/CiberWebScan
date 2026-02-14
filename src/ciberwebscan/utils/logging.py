"""
Logging utilities for CiberWebScan.

Provides centralized logging configuration.
"""

from __future__ import annotations

import logging
import logging.config
from pathlib import Path

from ciberwebscan.config.models import LoggingConfig


def setup_logging(config: LoggingConfig) -> None:
    """
    Configure logging based on the provided configuration.

    Args:
        config: Logging configuration from app config.
    """
    # Convert level string to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = level_map.get(config.level.upper(), logging.INFO)

    # Base logging configuration
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": config.format,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "level": level,
            },
        },
        "root": {
            "level": level,
            "handlers": ["console"],
        },
    }

    # Add file handler if file is specified
    if config.file:
        file_path = Path(config.file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        logging_config["handlers"]["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": str(file_path),
            "maxBytes": config.max_size,
            "backupCount": config.backup_count,
            "level": level,
        }
        logging_config["root"]["handlers"].append("file")

    # Apply configuration
    logging.config.dictConfig(logging_config)
