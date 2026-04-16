"""
API request models for CiberWebScan.

These Pydantic models define and validate all incoming API request payloads.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator

# =============================================================================
# Scrape Requests
# =============================================================================


class ScrapeRequest(BaseModel):
    """Request payload for scraping endpoint."""

    url: HttpUrl
    dynamic: bool = Field(
        default=False,
        description="Use playwright for JavaScript-rendered pages",
    )
    wait_for: str | None = Field(
        None,
        description="CSS selector to wait for (dynamic mode only)",
    )
    selector: str | None = Field(
        default=None,
        description="CSS selector used for focused extraction",
    )
    attributes: list[str] = Field(
        default_factory=list,
        description="Attributes to extract from matched elements",
    )
    extraction_schema: dict[str, Any] | None = Field(
        default=None,
        description="Structured extraction schema",
    )
    pagination_selector: str | None = Field(
        default=None,
        description="Selector for pagination links",
    )
    pagination_limit: Annotated[int, Field(ge=1, le=1000)] = Field(
        default=1,
        description="Maximum number of pages to traverse",
    )
    timeout: Annotated[float, Field(ge=1.0, le=120.0)] = 30.0
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Custom headers to send with request",
    )
    cookies: dict[str, str] = Field(
        default_factory=dict,
        description="Cookies to include in request",
    )
    proxy: str | None = Field(
        default=None,
        description="HTTP/HTTPS proxy URL",
    )
    user_agent: str | None = Field(
        default=None,
        description="Custom User-Agent string",
    )
    check_robots: bool = Field(
        default=True,
        description="Respect robots.txt when scraping",
    )
    export: str | None = Field(
        default=None,
        description="Optional output file path for exported results",
    )
    export_format: Literal["json", "jsonl", "csv"] = Field(
        default="json",
        description="Export format when export path is provided",
    )

    @field_validator("attributes", mode="before")
    @classmethod
    def parse_attributes(cls, value: list[str] | str | None) -> list[str]:
        """Allow attributes as list or comma-separated string."""
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


class ScrapeBatchRequest(BaseModel):
    """Request for batch scraping multiple URLs."""

    urls: list[HttpUrl] = Field(..., min_length=1, max_length=100)
    dynamic: bool = False
    selector: str | None = None
    timeout: Annotated[float, Field(ge=1.0, le=120.0)] = 30.0
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    proxy: str | None = None
    user_agent: str | None = None
    export: str | None = Field(
        default=None,
        description="Optional output file path for exported batch results",
    )
    export_format: Literal["json", "jsonl", "csv"] = Field(
        default="jsonl",
        description="Export format when export path is provided",
    )

    @field_validator("urls")
    @classmethod
    def unique_urls(cls, v: list[HttpUrl]) -> list[HttpUrl]:
        """Ensure URLs are unique."""
        seen = set()
        unique = []
        for url in v:
            url_str = str(url)
            if url_str not in seen:
                seen.add(url_str)
                unique.append(url)
        return unique


# =============================================================================
# Analyze Requests
# =============================================================================


class AnalyzeRequest(BaseModel):
    """Request payload for analysis endpoint."""

    url: HttpUrl
    ssl: bool = Field(default=True, description="Perform SSL/TLS analysis")
    fingerprint: bool = Field(default=True, description="Detect technologies")
    analyze_headers: bool = Field(
        default=True,
        description="Analyze security headers",
    )
    cve: bool = Field(default=True, description="Lookup CVEs for detected technologies")
    ssl_verify: bool = Field(
        default=True,
        description="Verify SSL certificates when fetching target page",
    )
    timeout: Annotated[float, Field(ge=1.0, le=300.0)] = 30.0
    ssl_timeout: Annotated[float, Field(ge=1.0, le=120.0)] = 10.0
    deep_scan: bool = Field(
        default=False,
        description="Enable deeper technology fingerprinting",
    )
    cve_sources: list[Literal["nvd", "vulners", "circl"]] = Field(
        default_factory=list,
        description="Explicit CVE sources. If empty, config value is used",
    )
    cve_limit: Annotated[int, Field(ge=1, le=1000)] = 100
    cve_severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Custom HTTP headers for analysis requests",
    )
    cookies: dict[str, str] = Field(default_factory=dict)
    proxy: str | None = None
    user_agent: str | None = None
    check_robots: bool = False
    enrich_exploits: bool = False
    export: str | None = Field(
        default=None,
        description="Optional output file path for exported results",
    )
    export_format: Literal["json", "jsonl", "csv"] = Field(
        default="json",
        description="Export format when export path is provided",
    )

    @field_validator("cve_sources", mode="before")
    @classmethod
    def parse_cve_sources(
        cls,
        value: list[str] | str | None,
    ) -> list[str]:
        """Allow CVE sources as list or comma-separated string."""
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


# =============================================================================
# Attack Requests
# =============================================================================


class AttackRequest(BaseModel):
    """Request payload for attack simulation endpoint."""

    url: HttpUrl
    xss: bool | None = Field(
        default=None,
        description="Test for XSS vulnerabilities (None uses config default)",
    )
    sqli: bool | None = Field(
        default=None,
        description="Test for SQL injection (None uses config default)",
    )
    traversal: bool | None = Field(
        default=None,
        description="Test for path traversal (None uses config default)",
    )
    enumeration: bool | None = Field(
        default=None,
        description="Directory enumeration (None uses config default)",
    )
    all_attacks: bool = Field(
        default=False,
        description="Enable all attack types",
    )
    intensity: Literal["low", "medium", "high"] = "medium"
    max_payloads: Annotated[int | None, Field(ge=1, le=1000)] = None
    custom_payloads_file: str | None = Field(
        default=None,
        description="Path to custom payloads file",
    )
    custom_wordlist: str | None = Field(
        default=None,
        description="Custom wordlist path for enumeration",
    )
    timeout: Annotated[float, Field(ge=1.0, le=300.0)] = 10.0
    delay_between_requests: float = 0.1
    concurrent_requests: Annotated[int, Field(ge=1, le=10)] = 1
    scope_urls: list[str] = Field(
        default_factory=list,
        description="Optional list of URLs to scope the attack to",
    )
    skip_dangerous_payloads: bool = Field(
        default=True,
        description="Skip payloads marked as dangerous",
    )
    export: str | None = Field(
        default=None,
        description="Optional output file path for exported results",
    )
    export_format: Literal["json", "jsonl", "csv"] = Field(
        default="json",
        description="Export format when export path is provided",
    )
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    proxy: str | None = None
    user_agent: str | None = None
    verbose: bool = False
    user_consent: bool = Field(
        default=False,
        description="User confirms authorization to test this target",
    )

    @field_validator("user_consent")
    @classmethod
    def require_consent(cls, v: bool) -> bool:
        """Attack simulation requires explicit consent."""
        if not v:
            raise ValueError(
                "Attack simulation requires user_consent=true. "
                "Only test systems you own or have explicit permission to test."
            )
        return v

    @field_validator("headers", "cookies", mode="before")
    @classmethod
    def parse_key_value_map(
        cls,
        value: dict[str, str] | str | None,
    ) -> dict[str, str]:
        """Allow maps as dict or JSON object string."""
        if value is None:
            return {}
        if isinstance(value, str):
            try:
                loaded = json.loads(value)
                if isinstance(loaded, dict):
                    return {str(k): str(v) for k, v in loaded.items()}
            except json.JSONDecodeError:
                return {}
            return {}
        return value


# =============================================================================
# Export Requests
# =============================================================================


class ExportRequest(BaseModel):
    """Request for exporting results."""

    job_id: str = Field(..., description="Job ID from a previous operation")
    format: Literal["jsonl", "json", "csv"] = "jsonl"
    include_raw_html: bool = False
    include_screenshots: bool = False


# =============================================================================
# Configuration Requests
# =============================================================================


class ConfigUpdateRequest(BaseModel):
    """Request to update a configuration value."""

    path: str = Field(
        ...,
        min_length=1,
        description="Configuration key (dot-notation)",
    )
    value: Any = Field(..., description="New value (str, int, float, bool, list, dict)")
    save: bool = Field(
        False,
        description="If True, persist changes to disk immediately",
    )


class ConfigResetRequest(BaseModel):
    """Request to reset configuration."""

    path: Annotated[str | None, Field(min_length=1)] = Field(
        None,
        description="Specific key to reset, or None to reset all",
    )
    save: bool = Field(
        False,
        description="If True, persist reset to disk immediately",
    )


class ConfigExportRequest(BaseModel):
    """Request to export configuration."""

    path: str = Field(..., min_length=1, description="Output file path")
    format: str = Field(
        "yaml",
        description="Export format (yaml or json)",
    )


class ConfigLoadRequest(BaseModel):
    """Request to load configuration from file."""

    path: str = Field(..., min_length=1, description="Input file path")


class ConfigSaveRequest(BaseModel):
    """Request to save configuration to file."""

    path: Annotated[str | None, Field(min_length=1)] = Field(
        None,
        description="Output file path (uses default if not provided)",
    )


# =============================================================================
# Download Requests
# =============================================================================


class DownloadRequest(BaseModel):
    """Request to download a file using a token."""

    token: str = Field(
        ...,
        min_length=36,
        max_length=36,
        description="Download token (UUID format)",
    )


# =============================================================================
# Common Query Parameters (for use with FastAPI Depends)
# =============================================================================


class PaginationParams(BaseModel):
    """Common pagination parameters."""

    page: Annotated[int, Field(ge=1)] = 1
    page_size: Annotated[int, Field(ge=1, le=100)] = 20

    @property
    def offset(self) -> int:
        """Calculate offset for database queries."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Alias for page_size."""
        return self.page_size


class FilterParams(BaseModel):
    """Common filter parameters for list endpoints."""

    severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    since: str | None = Field(None, description="ISO datetime string")
    until: str | None = Field(None, description="ISO datetime string")
    search: str | None = Field(None, max_length=200)
