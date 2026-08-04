"""
Configuration package for CiberWebScan.

Provides configuration models, defaults, and loading utilities.
"""

from __future__ import annotations

from ciberwebscan.config.models import (
    AnalysisConfig,
    AppConfig,
    AttackConfig,
    CacheConfig,
    CVEConfig,
    DynamicScrapingConfig,
    ExportConfig,
    FingerprintConfig,
    HeadersAnalysisConfig,
    HTTPConfig,
    LoggingConfig,
    PaginationConfig,
    ProxyConfig,
    RateLimitConfig,
    RetryConfig,
    ScrapingConfig,
    SSLAnalysisConfig,
    TimeoutConfig,
    UserAgentConfig,
)

__all__ = [
    # Root config
    "AppConfig",
    # HTTP
    "HTTPConfig",
    "TimeoutConfig",
    "RetryConfig",
    "RateLimitConfig",
    "ProxyConfig",
    # User Agent
    "UserAgentConfig",
    # Scraping
    "ScrapingConfig",
    "PaginationConfig",
    "DynamicScrapingConfig",
    # Analysis
    "AnalysisConfig",
    "SSLAnalysisConfig",
    "FingerprintConfig",
    "CVEConfig",
    "HeadersAnalysisConfig",
    # Attack
    "AttackConfig",
    # Export
    "ExportConfig",
    # Logging
    "LoggingConfig",
    # Cache
    "CacheConfig",
]
