"""
Quick scan routes for CiberWebScan API.

Provides endpoints for combined analysis + attacks + scraping using presets.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from ciberwebscan.api.models.requests import QuickScanRequest
from ciberwebscan.api.models.responses import ErrorResponse, QuickScanResponse
from ciberwebscan.services.quick_service import QuickOptions, QuickService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/scan",
    response_model=QuickScanResponse,
    summary="Quick combined scan",
    description=(
        "Perform a combined scan using presets:\n"
        "- **low**: SSL, fingerprint, headers (no attacks, no CVEs)\n"
        "- **medium**: Analysis + moderate attacks (XSS, SQLi) - requires consent\n"
        "- **high**: Full analysis + all attacks + CVEs - requires consent\n\n"
        "Scraping is enabled when `selector` or `dynamic` is provided."
    ),
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def quick_scan(request: QuickScanRequest) -> QuickScanResponse:
    """
    Execute a quick scan combining analysis, attacks, and scraping.

    The preset controls which services run:
    - low: SSL + fingerprint + headers only
    - medium: + CVE + XSS + SQLi (requires consent)
    - high: + all attacks + traversal + enumeration (requires consent)

    Scraping runs when selector or dynamic is provided.
    """
    try:
        # Validate consent for medium/high
        preset = request.preset.lower()
        if preset in ("medium", "high") and not request.user_consent:
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "error": f"User consent is required for '{preset}' preset. "
                    "Set user_consent=true to confirm you have permission to test this system.",
                    "error_code": "CONSENT_REQUIRED",
                },
            )

        # Build options
        options = QuickOptions(
            url=str(request.url),
            preset=preset,
            timeout=request.timeout,
            proxy=request.proxy,
            user_agent=request.user_agent,
            headers=request.headers,
            cookies=request.cookies,
            consent=request.user_consent,
            selector=request.selector,
            dynamic=request.dynamic,
            output=None,  # No file export via API
            export_format=request.output_format,
            json_output=False,
            quiet=True,
            verbose=False,
        )

        # Execute scan
        service = QuickService()
        result = service.quick_scan(options)

        if not result.success:
            raise HTTPException(
                status_code=500,
                detail={
                    "success": False,
                    "error": result.error or "Quick scan failed",
                    "error_code": result.error_code or "QUICK_SCAN_ERROR",
                },
            )

        return QuickScanResponse(
            success=True,
            data=result.data,
            preset=preset,
            duration_seconds=result.duration_seconds,
            warnings=result.warnings,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Quick scan API error: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "error": str(e),
                "error_code": "INTERNAL_ERROR",
            },
        ) from e


@router.get(
    "/presets",
    summary="List available presets",
    description="Returns the configuration for all available scan presets.",
)
async def list_presets() -> dict:
    """List available scan presets and their configurations."""
    from ciberwebscan.services.quick_service import PRESETS

    return {
        "presets": {
            name: {
                "analyze": config["analyze"],
                "has_attacks": config["attack"] is not None,
                "attack_types": (
                    [k for k, v in config["attack"].items() if v is True]
                    if config["attack"]
                    else []
                ),
                "intensity": config["attack"]["intensity"]
                if config["attack"]
                else None,
                "scrape_dynamic": config["scrape"]["dynamic"],
            }
            for name, config in PRESETS.items()
        }
    }
