"""
Attack simulation endpoints for CiberWebScan API.

WARNING: Only use against systems you own or have explicit written permission
to test. Unauthorized security testing is illegal and unethical.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError

from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.api.helpers.download_helper import enrich_response_with_token
from ciberwebscan.api.models.requests import AttackRequest
from ciberwebscan.api.models.responses import APIResponse
from ciberwebscan.export.models import AttackResult
from ciberwebscan.services.attack_service import AttackOptions, AttackService
from ciberwebscan.services.base import ValidationError as ServiceValidationError
from ciberwebscan.services.download_service import DownloadService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/attack", response_model=APIResponse[AttackResult])
def attack_target(
    request: AttackRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[AttackResult]:
    """
    Perform security attack simulations against a target URL.

    Supports XSS, SQL injection, path traversal, and directory enumeration testing.

    **IMPORTANT**: Only test systems you own or have explicit written permission to test.
    Setting `user_consent=true` confirms that you have that permission.
    """
    try:
        from ciberwebscan.config.loader import get_config as get_app_config

        app_config = get_app_config()

        # Resolve individual attack flags; all_attacks overrides each one
        xss = True if request.all_attacks else request.xss
        sqli = True if request.all_attacks else request.sqli
        traversal = True if request.all_attacks else request.traversal
        enumeration = True if request.all_attacks else request.enumeration
        csrf = True if request.all_attacks else request.csrf
        subdomain = True if request.all_attacks else request.subdomain
        command_injection = True if request.all_attacks else request.command_injection

        options = AttackOptions(
            url=str(request.url),
            user_consent=request.user_consent,
            config=app_config.attack,
            xss=xss,
            sqli=sqli,
            traversal=traversal,
            enumeration=enumeration,
            csrf=csrf,
            subdomain=subdomain,
            command_injection=command_injection,
            intensity=request.intensity,
            max_payloads=request.max_payloads,
            timeout=request.timeout,
            delay_between_requests=request.delay_between_requests,
            concurrent_requests=request.concurrent_requests,
            custom_payloads_file=request.custom_payloads_file,
            custom_wordlist=request.custom_wordlist,
            json_body=request.json_body,
            skip_dangerous_payloads=request.skip_dangerous_payloads,
            scope_urls=request.scope_urls,
            export=request.export,
            export_format=request.export_format,
            headers=request.headers,
            cookies=request.cookies,
            proxy=request.proxy,
            user_agent=request.user_agent,
            verbose=request.verbose,
        )

        service = AttackService()
        result = service.attack(options)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.error or "Attack execution failed",
            )

        # Enrich response with download token
        download_service = DownloadService()
        data, download_token = enrich_response_with_token(
            result, user.identifier, download_service
        )
        download_url = f"/api/v1/download/{download_token}" if download_token else None

        return APIResponse[AttackResult](
            success=True,
            data=data,
            download_token=download_token,
            download_url=download_url,
        )

    except ServiceValidationError as e:
        logger.warning(f"Validation error in attack request for {request.url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except ValidationError as e:
        logger.warning(f"Pydantic validation error in attack request: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid request: {e}",
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error running attack execution on {request.url}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Attack execution failed: {str(e)}",
        ) from e
