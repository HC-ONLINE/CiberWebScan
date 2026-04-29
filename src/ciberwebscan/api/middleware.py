"""
Middleware for CiberWebScan API.

Provides request logging, rate limiting, and other cross-cutting concerns.
"""

from __future__ import annotations

import logging
import time
from collections import Counter

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all HTTP requests with timing information."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            status_code = 500
            raise e from None
        finally:
            duration = time.perf_counter() - start_time
            logger.info(
                f"{request.method} {path} - {status_code} ({duration:.3f}s)",
                extra={
                    "method": request.method,
                    "path": path,
                    "status_code": status_code,
                    "client_ip": client_ip,
                    "duration": duration,
                },
            )
        return response


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware."""

    def __init__(self, app, requests_per_minute: int):
        super().__init__(app)
        self.limit = requests_per_minute
        self.counts = Counter()
        self.window = 0

    async def dispatch(self, request: Request, call_next) -> Response:
        # Identificación de cliente (Prioriza X-Forwarded-For)
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[
            0
        ].strip() or (request.client.host if request.client else "unknown")

        now = time.time()
        current_window = int(now // 60)

        # Rotación de ventana
        if current_window != self.window:
            self.counts.clear()
            self.window = current_window

        # Verificación de límite
        if self.counts[client_ip] >= self.limit:
            retry_after = 60 - int(now % 60)
            logger.warning(f"Rate limit exceeded: {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        self.counts[client_ip] += 1
        return await call_next(request)


def add_request_logging_middleware(app: FastAPI) -> None:
    """Add request logging middleware to FastAPI app."""
    app.add_middleware(RequestLoggingMiddleware)


def add_rate_limiting_middleware(app: FastAPI, requests_per_minute: int = 60) -> None:
    """Add rate limiting middleware to FastAPI app."""
    app.add_middleware(RateLimitingMiddleware, requests_per_minute=requests_per_minute)
