"""
Configuration models for CiberWebScan.

These Pydantic models define the structure and validation rules for all
configuration options. They replace the complex multi-file config system
with a single, validated configuration schema.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


# =============================================================================
# HTTP Client Configuration
# =============================================================================


class TimeoutConfig(BaseModel):
    """HTTP timeout settings."""

    connect: Annotated[float, Field(ge=0.1, le=300.0)] = 10.0
    read: Annotated[float, Field(ge=0.1, le=600.0)] = 30.0
    write: Annotated[float, Field(ge=0.1, le=600.0)] = 30.0
    pool: Annotated[float, Field(ge=0.1, le=300.0)] = 10.0


class RetryConfig(BaseModel):
    """HTTP retry settings with exponential backoff."""

    max_attempts: Annotated[int, Field(ge=1, le=10)] = 3
    backoff_factor: Annotated[float, Field(ge=0.1, le=10.0)] = 0.5
    retryable_status_codes: list[int] = Field(
        default=[429, 500, 502, 503, 504],
        description="HTTP status codes that trigger a retry",
    )


class RateLimitConfig(BaseModel):
    """Rate limiting settings."""

    requests_per_second: Annotated[float, Field(ge=0.1, le=100.0)] = 5.0
    per_domain: bool = True


class ProxyConfig(BaseModel):
    """Proxy server configuration."""

    http: HttpUrl | None = None
    https: HttpUrl | None = None
    socks5: str | None = Field(None, pattern=r"^socks5://[\w\.\-]+:\d+$")
    rotate: bool = False
    rotation_interval: Annotated[int, Field(ge=1)] = 10


class HTTPConfig(BaseModel):
    """Complete HTTP client configuration."""

    timeout: TimeoutConfig = Field(default_factory=lambda: TimeoutConfig())
    retry: RetryConfig = Field(default_factory=lambda: RetryConfig())
    rate_limit: RateLimitConfig = Field(default_factory=lambda: RateLimitConfig())
    proxy: ProxyConfig | None = None
    http2: bool = True
    follow_redirects: bool = True
    max_redirects: Annotated[int, Field(ge=1, le=20)] = 10
    verify_ssl: bool = True


# =============================================================================
# User Agent Configuration
# =============================================================================



# Default user agents for rotation (can be overridden in config.yaml)
DEFAULT_USER_AGENTS: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    # Safari on iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


class UserAgentConfig(BaseModel):
    """User agent rotation settings."""

    mode: Literal["static", "rotate", "random"] = "rotate"
    custom: str | None = Field(
        default=None,
        description="Custom user agent string (used when mode='static')",
    )
    rotate_interval: Annotated[int, Field(ge=1)] = 10
    agents: list[str] = Field(
        default_factory=lambda: DEFAULT_USER_AGENTS.copy(),
        description="List of user agents for rotation/random selection",
    )


# =============================================================================
# Scraping Configuration
# =============================================================================


class PaginationConfig(BaseModel):
    """Pagination handling for scraping."""

    enabled: bool = False
    max_pages: Annotated[int, Field(ge=1, le=1000)] = 10
    next_selector: str | None = Field(
        default=None,
        description="CSS selector for next page link",
    )
    page_param: str | None = Field(
        default=None,
        description="Query parameter name for page number",
    )


class DynamicScrapingConfig(BaseModel):
    """Selenium/dynamic scraping settings."""

    enabled: bool = False
    wait_timeout: Annotated[float, Field(ge=1.0, le=120.0)] = 10.0
    wait_for_selector: str | None = None
    headless: bool = True
    browser: Literal["chrome", "firefox", "edge"] = "chrome"


class ScrapingConfig(BaseModel):
    """Complete scraping configuration."""

    dynamic: DynamicScrapingConfig = Field(default_factory=lambda: DynamicScrapingConfig())
    pagination: PaginationConfig = Field(default_factory=lambda: PaginationConfig())
    extract_links: bool = True
    extract_images: bool = True
    extract_scripts: bool = True
    extract_forms: bool = True
    max_content_length: Annotated[int, Field(ge=1024)] = 10 * 1024 * 1024  # 10MB


# =============================================================================
# Analysis Configuration
# =============================================================================


class SSLAnalysisConfig(BaseModel):
    """SSL/TLS analysis settings."""

    enabled: bool = True
    check_chain: bool = True
    check_revocation: bool = True
    check_expiry: bool = True
    warning_days: Annotated[int, Field(ge=1, le=365)] = 30


class FingerprintConfig(BaseModel):
    """Technology fingerprinting settings."""

    enabled: bool = True
    check_headers: bool = True
    check_html: bool = True
    check_scripts: bool = True
    check_cookies: bool = True
    check_dns: bool = False


class CVEConfig(BaseModel):
    """CVE lookup configuration."""

    enabled: bool = True
    api: Literal["nvd", "vulners", "circl", "all"] = "all"
    nvd_api_key: str | None = Field(default=None, description="NVD API key for higher rate limits")
    vulners_api_key: str | None = Field(default=None, description="Vulners API key")
    cache_ttl: Annotated[int, Field(ge=60)] = 86400  # 24 hours


class HeadersAnalysisConfig(BaseModel):
    """Security headers analysis settings."""

    enabled: bool = True
    required_headers: list[str] = Field(
        default=[
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
        ]
    )


class AnalysisConfig(BaseModel):
    """Complete analysis configuration."""

    ssl: SSLAnalysisConfig = Field(default_factory=lambda: SSLAnalysisConfig())
    fingerprint: FingerprintConfig = Field(default_factory=lambda: FingerprintConfig())
    cve: CVEConfig = Field(default_factory=lambda: CVEConfig())
    headers: HeadersAnalysisConfig = Field(default_factory=lambda: HeadersAnalysisConfig())


# =============================================================================
# Attack Simulation Configuration
# =============================================================================


class AttackConfig(BaseModel):
    """Attack simulation settings."""

    enabled: bool = False
    user_consent: bool = False
    whitelist: list[str] = Field(
        default=["127.0.0.1", "localhost"],
        description="Allowed targets for attack simulation",
    )
    xss: bool = True
    sqli: bool = True
    traversal: bool = True
    enumeration: bool = True
    max_payloads: Annotated[int, Field(ge=1, le=1000)] = 50

    @field_validator("whitelist", mode="before")
    @classmethod
    def ensure_list(cls, v: str | list[str]) -> list[str]:
        """Allow comma-separated string or list."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",")]
        return v


# =============================================================================
# Export Configuration
# =============================================================================


class ExportConfig(BaseModel):
    """Export settings."""

    format: Literal["jsonl", "json", "csv"] = "jsonl"
    output_dir: str = "exports"
    include_raw_html: bool = False
    include_screenshots: bool = False
    streaming: bool = True
    buffer_size: Annotated[int, Field(ge=1, le=10000)] = 100


# =============================================================================
# Logging Configuration
# =============================================================================


class LoggingConfig(BaseModel):
    """Logging settings."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: str | None = None
    max_size: Annotated[int, Field(ge=1024)] = 10 * 1024 * 1024  # 10MB
    backup_count: Annotated[int, Field(ge=0, le=100)] = 5


# =============================================================================
# Cache Configuration
# =============================================================================


class CacheConfig(BaseModel):
    """Cache settings."""

    enabled: bool = True
    directory: str = ".cache"
    ttl: Annotated[int, Field(ge=60)] = 3600  # 1 hour
    max_size_mb: Annotated[int, Field(ge=1, le=10240)] = 100


# =============================================================================
# Root Configuration
# =============================================================================


class AppConfig(BaseModel):
    """
    Root configuration model for CiberWebScan.

    This is the main configuration class that aggregates all subsections.
    It can be loaded from a YAML file or constructed programmatically.

    Example YAML:
        ```yaml
        http:
          timeout:
            connect: 10
            read: 30
          retry:
            max_attempts: 3
        scraping:
          dynamic:
            enabled: true
            browser: chrome
        analysis:
          ssl:
            warning_days: 30
          cve:
            api: nvd
        export:
          format: jsonl
          streaming: true
        ```
    """

    http: HTTPConfig = Field(default_factory=lambda: HTTPConfig())
    user_agent: UserAgentConfig = Field(default_factory=lambda: UserAgentConfig())
    scraping: ScrapingConfig = Field(default_factory=lambda: ScrapingConfig())
    analysis: AnalysisConfig = Field(default_factory=lambda: AnalysisConfig())
    attack: AttackConfig = Field(default_factory=lambda: AttackConfig())
    export: ExportConfig = Field(default_factory=lambda: ExportConfig())
    logging: LoggingConfig = Field(default_factory=lambda: LoggingConfig())
    cache: CacheConfig = Field(default_factory=lambda: CacheConfig())

    model_config = {
        "extra": "forbid",  # Reject unknown fields
        "validate_default": True,
    }
