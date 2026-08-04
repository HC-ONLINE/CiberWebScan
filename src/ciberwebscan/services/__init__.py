"""
Services layer for CiberWebScan.

This module provides orchestration services that coordinate core functionality.
CLI and API use these services as their interface to the application logic.

Services:
    - ScrapeService: Web scraping with optional export
    - AnalyzeService: Security analysis with optional export
    - AttackService: Attack simulation with optional export
    - QuickService: Combined scan (analysis + attacks + scraping)
    - ConfigService: Configuration management

Each service that produces results supports an optional export flag.
"""

from __future__ import annotations

from ciberwebscan.services.analyze_service import AnalyzeOptions, AnalyzeService
from ciberwebscan.services.attack_service import AttackOptions, AttackService
from ciberwebscan.services.base import (
    BaseService,
    ExecutionError,
    ServiceError,
    ServiceResult,
    ValidationError,
)
from ciberwebscan.services.config_service import ConfigService, ConfigValue
from ciberwebscan.services.quick_service import QuickOptions, QuickService
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
    "AttackService",
    "AttackOptions",
    "QuickService",
    "QuickOptions",
    "ConfigService",
    "ConfigValue",
]
