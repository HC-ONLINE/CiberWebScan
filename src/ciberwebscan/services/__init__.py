"""
Services layer for CiberWebScan.

This module provides orchestration services that coordinate core functionality.
CLI and API use these services as their interface to the application logic.

Services:
    - ScrapeService: Web scraping with optional export
    - AnalyzeService: Security analysis with optional export
    - ConfigService: Configuration management
    - AttackService: Attack simulation (future)

Each service that produces results supports an optional export flag.
"""

from ciberwebscan.services.analyze_service import AnalyzeOptions, AnalyzeService
from ciberwebscan.services.base import (
    BaseService,
    ExecutionError,
    ServiceError,
    ServiceResult,
    ValidationError,
)
from ciberwebscan.services.config_service import ConfigService, ConfigValue
from ciberwebscan.services.scrape_service import ScrapeOptions, ScrapeService

__all__ = [
    # Base
    "BaseService",
    "ServiceError",
    "ServiceResult",
    "ValidationError",
    "ExecutionError",
    # Services
    "ScrapeService",
    "ScrapeOptions",
    "AnalyzeService",
    "AnalyzeOptions",
    "ConfigService",
    "ConfigValue",
]
