"""
Health check endpoints for CiberWebScan API.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from ciberwebscan import __version__


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    timestamp: datetime
    version: str
    message: str


router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Basic health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version=__version__,
        message="CiberWebScan API is running",
    )


@router.get("/health/ready", response_model=HealthResponse)
async def readiness_check() -> HealthResponse:
    """Readiness check endpoint for container orchestration."""
    # Could add checks for database, external services, etc.
    return HealthResponse(
        status="ready",
        timestamp=datetime.now(timezone.utc),
        version=__version__,
        message="CiberWebScan API is ready to accept requests",
    )
