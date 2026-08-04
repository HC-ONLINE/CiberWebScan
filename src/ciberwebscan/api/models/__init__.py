"""
API models package.

Provides request and response models for the REST API.
"""

from __future__ import annotations

from ciberwebscan.api.models.requests import (
    AnalyzeRequest,
    AttackRequest,
    ConfigExportRequest,
    ConfigLoadRequest,
    ConfigResetRequest,
    ConfigSaveRequest,
    ConfigUpdateRequest,
    DownloadRequest,
    ExportRequest,
    FilterParams,
    PaginationParams,
    QuickScanRequest,
    ScrapeBatchRequest,
    ScrapeRequest,
)
from ciberwebscan.api.models.responses import (
    APIResponse,
    ConfigFileResponse,
    ConfigKeysResponse,
    ConfigValueResponse,
    DetailedHealthResponse,
    DownloadInfo,
    DownloadTokenResponse,
    ErrorResponse,
    ExportResponse,
    HealthCheckResponse,
    JobCreatedResponse,
    JobStatus,
    PaginatedResponse,
    QuickScanResponse,
    ScanSummaryResponse,
    ScrapeBatchResponse,
    ScrapeBatchResultResponse,
    SeveritySummary,
    ValidationErrorDetail,
    ValidationErrorResponse,
)

__all__ = [
    # Request models
    "ScrapeRequest",
    "ScrapeBatchRequest",
    "AnalyzeRequest",
    "AttackRequest",
    "ExportRequest",
    "ConfigUpdateRequest",
    "ConfigResetRequest",
    "ConfigExportRequest",
    "ConfigLoadRequest",
    "ConfigSaveRequest",
    "DownloadRequest",
    "QuickScanRequest",
    "PaginationParams",
    "FilterParams",
    # Response models
    "APIResponse",
    "ErrorResponse",
    "ValidationErrorDetail",
    "ValidationErrorResponse",
    "PaginatedResponse",
    "JobStatus",
    "JobCreatedResponse",
    "ScrapeBatchResponse",
    "ScrapeBatchResultResponse",
    "HealthCheckResponse",
    "DetailedHealthResponse",
    "SeveritySummary",
    "ScanSummaryResponse",
    "ExportResponse",
    "ConfigValueResponse",
    "ConfigKeysResponse",
    "ConfigFileResponse",
    "DownloadTokenResponse",
    "DownloadInfo",
    "QuickScanResponse",
]
