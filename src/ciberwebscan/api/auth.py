"""
Authentication module for CiberWebScan API.

Provides API Key authentication.
"""

from __future__ import annotations

import logging
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from ciberwebscan.config.loader import get_config

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================


class AuthConfig(BaseModel):
    """Authentication configuration."""

    api_key_enabled: bool = True
    api_keys: list[str] = []


def get_auth_config() -> AuthConfig:
    """
    Load authentication configuration from global config.
    """
    config = get_config()
    auth_cfg = config.api.auth

    return AuthConfig(
        api_key_enabled=bool(auth_cfg.api_keys),
        api_keys=auth_cfg.api_keys,
    )


# =============================================================================
# Security Schemes
# =============================================================================

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# =============================================================================
# Authentication Dependencies
# =============================================================================


class AuthenticatedUser(BaseModel):
    """Authenticated user/client information."""

    identifier: str
    auth_method: str
    scopes: list[str] = []


def _secure_compare_key(provided_key: str, stored_keys: list[str]) -> str | None:
    """
    Compare API key using constant-time comparison to prevent timing attacks.
    Returns the matched key identifier if valid, None otherwise.
    """
    for stored_key in stored_keys:
        if secrets.compare_digest(provided_key.encode(), stored_key.encode()):
            return stored_key[:8]
    return None


async def verify_api_key(
    request: Request,
    api_key: Annotated[str | None, Security(api_key_header)] = None,
) -> AuthenticatedUser | None:
    """
    Verify API key from X-API-Key header.

    Uses constant-time comparison to prevent timing attacks.

    Returns:
        AuthenticatedUser if valid, None if no key provided
    """
    client_ip = _get_client_ip(request)

    if not api_key:
        return None

    config = get_auth_config()

    if not config.api_key_enabled:
        logger.warning(
            "API key auth disabled but key provided",
            extra={"client_ip": client_ip},
        )
        return None

    # Constant-time comparison
    key_id = _secure_compare_key(api_key, config.api_keys)

    if key_id:
        logger.info(
            f"API key authenticated: {key_id}...",
            extra={
                "event": "auth_success",
                "key_id": key_id,
                "client_ip": client_ip,
            },
        )
        return AuthenticatedUser(
            identifier=f"apikey:{key_id}",
            auth_method="api_key",
            scopes=["full_access"],
        )

    # Log failed attempt
    logger.warning(
        f"Invalid API key attempt from {client_ip}",
        extra={
            "event": "auth_failed",
            "reason": "invalid_key",
            "client_ip": client_ip,
            "key_prefix": api_key[:4] + "..." if len(api_key) > 4 else "***",
        },
    )
    return None


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.client.host if request.client else "unknown"


async def get_current_user(
    api_key_user: Annotated[AuthenticatedUser | None, Depends(verify_api_key)],
    request: Request,
) -> AuthenticatedUser:
    """
    Get the current authenticated user.

    Checks API key from X-API-Key header.
    Raises 401 if not valid.
    """
    if api_key_user:
        return api_key_user

    # Log unauthorized access attempt
    client_ip = _get_client_ip(request)
    logger.warning(
        f"Unauthorized access attempt from {client_ip}: {request.method} {request.url.path}",
        extra={
            "event": "auth_required",
            "client_ip": client_ip,
            "method": request.method,
            "path": request.url.path,
        },
    )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide X-API-Key header.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


async def get_optional_user(
    api_key_user: Annotated[AuthenticatedUser | None, Depends(verify_api_key)],
) -> AuthenticatedUser | None:
    """
    Get the current user if authenticated, None otherwise.

    Useful for endpoints that have different behavior for authenticated users.
    """
    return api_key_user


# =============================================================================
# Scope/Permission Checking
# =============================================================================


def require_scope(required_scope: str):
    """
    Dependency factory that requires a specific scope.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_scope("admin"))])
        async def admin_endpoint():
            ...
    """

    async def check_scope(
        user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    ) -> AuthenticatedUser:
        if "full_access" in user.scopes:
            return user
        if required_scope not in user.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope}' required",
            )
        return user

    return check_scope


# =============================================================================
# Utility Functions
# =============================================================================


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return secrets.token_urlsafe(32)
