"""
Main FastAPI application for CiberWebScan.

Provides REST API endpoints for scraping, analysis, and attack simulation.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ciberwebscan import __description__, __version__
from ciberwebscan.api.middleware import (
    add_rate_limiting_middleware,
    add_request_logging_middleware,
)
from ciberwebscan.api.models.responses import ErrorResponse
from ciberwebscan.api.routes import (
    analyze,
    attack,
    auth,
    config,
    download,
    health,
    quick,
    scrape,
)
from ciberwebscan.config.loader import get_config
from ciberwebscan.services.cleanup_scheduler import get_scheduler

logger = logging.getLogger(__name__)

prefix = "/api"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Handle application startup and shutdown."""
    logger.info("Starting CiberWebScan API")

    # Start cleanup scheduler
    app_config = get_config()
    if app_config.download.enabled:
        scheduler = get_scheduler()
        scheduler.start()

    yield

    # Stop cleanup scheduler
    if app_config.download.enabled:
        scheduler = get_scheduler()
        scheduler.stop()

    logger.info("Shutting down CiberWebScan API")


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app_config = get_config()
    api_config = app_config.api

    app = FastAPI(
        title="CiberWebScan API",
        description=__description__,
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS from global config
    app.add_middleware(
        CORSMiddleware,
        allow_origins=api_config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add custom middleware
    add_request_logging_middleware(app)
    if api_config.rate_limit.enabled:
        add_rate_limiting_middleware(
            app, requests_per_minute=api_config.rate_limit.requests_per_minute
        )

    # Exception handlers
    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        """Handle validation errors."""
        logger.warning(f"Validation error on {request.url}: {exc}")
        error_response = ErrorResponse(
            error=str(exc),
            error_code="VALIDATION_ERROR",
        )
        return JSONResponse(
            status_code=400,
            content=jsonable_encoder(error_response),
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle unexpected errors."""
        logger.error(f"Unexpected error on {request.url}: {exc}", exc_info=True)
        error_response = ErrorResponse(
            error="Internal server error",
            error_code="INTERNAL_ERROR",
            details={"request_path": str(request.url.path)},
        )
        return JSONResponse(
            status_code=500,
            content=jsonable_encoder(error_response),
        )

    # Include routers
    app.include_router(health.router, tags=["health"])
    app.include_router(auth.router, prefix=prefix + "/auth", tags=["authentication"])
    app.include_router(config.router, prefix=prefix, tags=["configuration"])
    app.include_router(scrape.router, prefix=prefix, tags=["scraping"])
    app.include_router(analyze.router, prefix=prefix, tags=["analysis"])
    app.include_router(attack.router, prefix=prefix, tags=["attacks"])
    app.include_router(quick.router, prefix=prefix + "/quick", tags=["quick"])
    app.include_router(download.router, prefix=prefix, tags=["download"])

    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    app_config = get_config()

    uvicorn.run(
        "ciberwebscan.api.app:app",
        host=app_config.api.host,
        port=app_config.api.port,
        reload=True,
        log_level=app_config.logging.level.lower(),
    )
