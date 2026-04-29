"""
Authentication endpoints for CiberWebScan API.

Provides endpoints for API key management and user information.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ciberwebscan.api.auth import (
    AuthenticatedUser,
    generate_api_key,
    get_current_user,
)

router = APIRouter()


# =============================================================================
# Request/Response Models
# =============================================================================


class UserInfoResponse(BaseModel):
    """Response model for user information."""

    identifier: str
    auth_method: str
    scopes: list[str]
    authenticated: bool = True


class ApiKeyGenerateResponse(BaseModel):
    """Response for API key generation."""

    api_key: str
    message: str = "Store this key securely. It cannot be retrieved again."


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/me", response_model=UserInfoResponse)
async def get_current_user_info(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> UserInfoResponse:
    """
    Get information about the currently authenticated user.

    Requires authentication via API key.
    """
    return UserInfoResponse(
        identifier=user.identifier,
        auth_method=user.auth_method,
        scopes=user.scopes,
    )


@router.post("/generate-key", response_model=ApiKeyGenerateResponse)
async def generate_new_api_key(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> ApiKeyGenerateResponse:
    """
    Generate a new API key.

    Note: This only generates the key value. You must manually add it to
    the CIBERWEBSCAN_API_KEYS environment variable for it to work.

    Requires authentication.
    """
    # Check if user has permission (full_access or admin scope)
    if "full_access" not in user.scopes and "admin" not in user.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to generate API keys",
        )

    new_key = generate_api_key()

    return ApiKeyGenerateResponse(
        api_key=new_key,
        message=(
            "Store this key securely. It cannot be retrieved again. "
            "Add it to CIBERWEBSCAN_API_AUTH_API_KEYS environment variable to activate."
        ),
    )
