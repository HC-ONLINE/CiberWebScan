"""
API models package.

Provides request and response models for the REST API.
"""

from ciberwebscan.api.models.requests import (
    AnalyzeRequest,
    AttackRequest,
    ConfigUpdateRequest,
    ExportRequest,
    FilterParams,
    PaginationParams,
    ScrapeBatchRequest,
    ScrapeRequest,
)
from ciberwebscan.api.models.responses import (
    AnalyzeResponse,
    APIResponse,
    AttackResponse,
    ConfigFileResponse,
    ConfigKeysResponse,
    ConfigValueResponse,
    CVESearchResponse,
    DetailedHealthResponse,
    ErrorResponse,
    ExportResponse,
    FingerprintResponse,
    HeadersAnalysisResponse,
    HealthCheckResponse,
    JobCreatedResponse,
    JobStatus,
    PaginatedResponse,
    ScanSummaryResponse,
    ScrapeBatchResponse,
    ScrapeBatchResultResponse,
    ScrapeResponse,
    SeveritySummary,
    SSLAnalysisResponse,
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
    "ScrapeResponse",
    "ScrapeBatchResponse",
    "ScrapeBatchResultResponse",
    "AnalyzeResponse",
    "SSLAnalysisResponse",
    "FingerprintResponse",
    "HeadersAnalysisResponse",
    "CVESearchResponse",
    "AttackResponse",
    "HealthCheckResponse",
    "DetailedHealthResponse",
    "SeveritySummary",
    "ScanSummaryResponse",
    "ExportResponse",
    "ConfigValueResponse",
    "ConfigKeysResponse",
    "ConfigFileResponse",
]
