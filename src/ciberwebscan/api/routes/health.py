"""
Health check endpoints for CiberWebScan API.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from ciberwebscan import __version__
from ciberwebscan.api.models.responses import HealthCheckResponse

router = APIRouter()


@router.get("/health", response_model=HealthCheckResponse)
async def health_check() -> HealthCheckResponse:
    """Basic health check endpoint."""
    return HealthCheckResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version=__version__,
        message="CiberWebScan API is running",
    )


@router.get("/health/ready", response_model=HealthCheckResponse)
async def readiness_check() -> HealthCheckResponse:
    """Readiness check endpoint for container orchestration."""
    # Could add checks for database, external services, etc.
    return HealthCheckResponse(
        status="ready",
        timestamp=datetime.now(timezone.utc),
        version=__version__,
        message="CiberWebScan API is ready to accept requests",
    )
