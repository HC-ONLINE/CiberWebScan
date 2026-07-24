"""
API response models for CiberWebScan.

These Pydantic models define the structure of all API responses.
They extend the export models with API-specific fields.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

from ciberwebscan.export.models import AnalysisReport, ScrapeResult

T = TypeVar("T")


# =============================================================================
# Base Response Models
# =============================================================================


class APIResponse(BaseModel, Generic[T]):
    """Generic API response wrapper."""

    success: bool = True
    data: T | None = None
    error: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    download_token: str | None = None
    download_url: str | None = None


class ErrorResponse(BaseModel):
    """Error response model."""

    success: bool = False
    error: str
    error_code: str | None = None
    details: dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ValidationErrorDetail(BaseModel):
    """Validation error detail."""

    field: str
    message: str
    value: Any | None = None


class ValidationErrorResponse(BaseModel):
    """Response for validation errors."""

    success: bool = False
    error: str = "Validation error"
    error_code: str = "VALIDATION_ERROR"
    details: list[ValidationErrorDetail]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Pagination Response
# =============================================================================


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""

    success: bool = True
    data: list[T]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_prev: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(
        cls,
        items: list[T],
        page: int,
        page_size: int,
        total: int,
    ) -> PaginatedResponse[T]:
        """Factory method to create paginated response."""
        total_pages = (total + page_size - 1) // page_size
        return cls(
            data=items,
            page=page,
            page_size=page_size,
            total_items=total,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        )


# =============================================================================
# Job/Async Operation Responses
# =============================================================================


class JobStatus(BaseModel):
    """Status of an async job."""

    job_id: str
    status: str = Field(
        ...,
        description="pending, running, completed, failed",
    )
    progress: int = Field(default=0, ge=0, le=100)
    message: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result_url: str | None = Field(
        None,
        description="URL to fetch results when completed",
    )


class JobCreatedResponse(BaseModel):
    """Response when a new job is created."""

    success: bool = True
    job_id: str
    status: str = "pending"
    status_url: str
    message: str = "Job created successfully"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScrapeBatchResponse(BaseModel):
    """Response for batch scrape endpoint."""

    success: bool = True
    job_id: str
    total_urls: int
    status_url: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScrapeBatchResultResponse(BaseModel):
    """Result of completed batch scrape."""

    job_id: str
    results: list[ScrapeResult]
    failed_urls: list[dict[str, str]] = Field(
        default_factory=list,
        description="URLs that failed with error messages",
    )
    total_success: int
    total_failed: int
    elapsed_seconds: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Health/Status Responses
# =============================================================================


class HealthCheckResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str
    message: str = ""
    uptime_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ServiceStatus(BaseModel):
    """Status of an individual service/component."""

    name: str
    status: str = "ok"  # ok, degraded, error
    latency_ms: float | None = None
    message: str = ""


class DetailedHealthResponse(BaseModel):
    """Detailed health check with component status."""

    status: str = "healthy"
    version: str
    uptime_seconds: float
    services: list[ServiceStatus] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Summary/Statistics Responses
# =============================================================================


class SeveritySummary(BaseModel):
    """Summary of findings by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanSummaryResponse(BaseModel):
    """Summary of a scan/analysis."""

    success: bool = True
    target_url: str
    scan_type: str  # scrape, analyze, attack
    duration_seconds: float
    total_findings: int
    severity_summary: SeveritySummary
    risk_score: int = Field(ge=0, le=100)
    top_issues: list[str] = Field(
        default_factory=list,
        description="Top 5 most critical issues found",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Export Responses
# =============================================================================


class ExportResponse(BaseModel):
    """Response for export endpoint."""

    success: bool = True
    download_url: str
    format: str
    file_size_bytes: int
    expires_at: datetime
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Download Responses
# =============================================================================


class DownloadTokenResponse(BaseModel):
    """Response when a download token is generated."""

    token: str = Field(..., description="Unique download token")
    expires_at: datetime = Field(..., description="Token expiration timestamp")
    download_url: str = Field(..., description="URL to download the file")


class DownloadInfo(BaseModel):
    """Metadata about a download token and associated file."""

    token: str
    user_id: str
    file_size_bytes: int
    created_at: datetime
    expires_at: datetime
    attempts_remaining: int
    file_format: str = Field(
        default="json", description="Export format (json/jsonl/csv)"
    )


# =============================================================================
# Configuration Responses
# =============================================================================


class ConfigValueResponse(BaseModel):
    """Response containing a configuration value and metadata."""

    key: str
    value: Any
    default: Any
    source: str  # 'file', 'env', 'default', 'runtime'
    description: str = ""


class ConfigKeysResponse(BaseModel):
    """Response containing a list of configuration keys."""

    keys: list[str]
    count: int


class ConfigFileResponse(BaseModel):
    """Response containing file operation result."""

    file_path: str
    operation: str  # 'export', 'load', 'save'
    format: str | None = None


# =============================================================================
# Quick Scan Responses
# =============================================================================


class QuickScanResponse(APIResponse[AnalysisReport]):
    """Response for quick scan endpoint."""

    preset: str = Field(description="Preset used for the scan")
    duration_seconds: float = 0.0
    warnings: list[str] = Field(
        default_factory=list,
        description="Warnings during scan execution",
    )
