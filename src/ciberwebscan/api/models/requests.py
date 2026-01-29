"""
API request models for CiberWebScan.

These Pydantic models define and validate all incoming API request payloads.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


# =============================================================================
# Scrape Requests
# =============================================================================


class ScrapeRequest(BaseModel):
    """Request payload for scraping endpoint."""

    url: HttpUrl
    dynamic: bool = Field(
        default=False,
        description="Use Selenium for JavaScript-rendered pages",
    )
    wait_for_selector: str | None = Field(
        None,
        description="CSS selector to wait for (dynamic mode only)",
    )
    extract_links: bool = True
    extract_images: bool = True
    extract_forms: bool = True
    extract_scripts: bool = True
    include_raw_html: bool = False
    timeout: Annotated[float, Field(ge=1.0, le=120.0)] = 30.0
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Custom headers to send with request",
    )
    cookies: dict[str, str] = Field(
        default_factory=dict,
        description="Cookies to include in request",
    )


class ScrapeBatchRequest(BaseModel):
    """Request for batch scraping multiple URLs."""

    urls: list[HttpUrl] = Field(..., min_length=1, max_length=100)
    dynamic: bool = False
    concurrency: Annotated[int, Field(ge=1, le=10)] = 5
    include_raw_html: bool = False

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
    headers: bool = Field(default=True, description="Analyze security headers")
    cve: bool = Field(default=True, description="Lookup CVEs for detected technologies")
    cve_api: Literal["nvd", "vulners", "circl", "all"] = "all"
    full_report: bool = Field(
        default=True,
        description="Include scrape results in report",
    )


# =============================================================================
# Attack Requests
# =============================================================================


class AttackRequest(BaseModel):
    """Request payload for attack simulation endpoint."""

    url: HttpUrl
    xss: bool = Field(default=True, description="Test for XSS vulnerabilities")
    sqli: bool = Field(default=True, description="Test for SQL injection")
    traversal: bool = Field(default=True, description="Test for path traversal")
    enumeration: bool = Field(default=True, description="Directory enumeration")
    max_payloads: Annotated[int, Field(ge=1, le=1000)] = 50
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
    """Request to update configuration."""

    path: str = Field(
        ...,
        description="Dot-separated path to config key (e.g., 'http.timeout.connect')",
    )
    value: str | int | float | bool | list | dict = Field(
        ...,
        description="New value for the configuration key",
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
