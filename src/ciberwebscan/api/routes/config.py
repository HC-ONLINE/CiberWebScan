"""
Configuration management endpoints for CiberWebScan API.

Provides REST endpoints for:
- Viewing and modifying configuration
- Exporting/importing configuration
- Resetting to defaults
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from ciberwebscan.api.auth import AuthenticatedUser, get_current_user
from ciberwebscan.api.models.requests import (
    ConfigExportRequest,
    ConfigLoadRequest,
    ConfigResetRequest,
    ConfigSaveRequest,
    ConfigUpdateRequest,
)
from ciberwebscan.api.models.responses import (
    APIResponse,
    ConfigFileResponse,
    ConfigKeysResponse,
    ConfigValueResponse,
)
from ciberwebscan.services.config_service import ConfigService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/config",
    response_model=APIResponse[dict[str, Any]],
    summary="Get all configuration",
)
async def get_all_config(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[dict[str, Any]]:
    """
    Retrieve the complete configuration.

    Returns all configuration sections and their values.
    """
    try:
        service = ConfigService()
        result = service.get_all()

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to get configuration",
            )

        return APIResponse[dict[str, Any]](data=result.data)

    except Exception as e:
        logger.error(f"Error getting configuration: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get configuration: {str(e)}",
        ) from e


@router.get(
    "/config/sections/{section}",
    response_model=APIResponse[dict[str, Any]],
    summary="Get configuration section",
)
async def get_config_section(
    section: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[dict[str, Any]]:
    """
    Retrieve a specific configuration section.

    Args:
        section: Section name (e.g., 'scraping', 'analysis', 'api')

    Returns:
        Configuration values for the specified section.
    """
    try:
        service = ConfigService()
        result = service.get_section(section)

        if not result.success:
            if "not found" in (result.error or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=result.error or f"Section not found: {section}",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to get section",
            )

        return APIResponse[dict[str, Any]](data=result.data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting section {section}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get section: {str(e)}",
        ) from e


@router.get(
    "/config/value",
    response_model=APIResponse[ConfigValueResponse],
    summary="Get a specific configuration value",
)
async def get_config_value(
    path: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[ConfigValueResponse]:
    """
    Retrieve a specific configuration value with metadata.

    Args:
        path: Configuration key in dot-notation (e.g., 'scraping.timeout')

    Returns:
        Value, default, source, and description.
    """
    try:
        service = ConfigService()
        result = service.get(path)

        if not result.success:
            if "not found" in (result.error or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=result.error or f"Key not found: {path}",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to get value",
            )

        data = result.data
        if data is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Configuration value data was None",
            )

        response_data = ConfigValueResponse(
            key=data.key,
            value=data.value,
            default=data.default,
            source=data.source,
            description=data.description,
        )

        return APIResponse[ConfigValueResponse](data=response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting config value {path}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get value: {str(e)}",
        ) from e


@router.put(
    "/config",
    response_model=APIResponse[ConfigValueResponse],
    summary="Update a configuration value",
)
async def update_config(
    request: ConfigUpdateRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[ConfigValueResponse]:
    """
    Update a configuration value.

    Args:
        request: Contains key path, new value, and optional save flag.

    Returns:
        Updated configuration value with metadata.
    """
    try:
        service = ConfigService()
        result = service.set(request.path, request.value)

        if not result.success:
            if "not found" in (result.error or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=result.error or f"Key not found: {request.path}",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to update configuration",
            )

        # Optionally save to disk
        if request.save:
            save_result = service.save()
            if not save_result.success:
                logger.warning(f"Failed to save config: {save_result.error}")

        data = result.data
        if data is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Configuration value data was None",
            )

        response_data = ConfigValueResponse(
            key=data.key,
            value=data.value,
            default=data.default,
            source=data.source,
            description=data.description,
        )

        return APIResponse[ConfigValueResponse](data=response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating config {request.path}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update configuration: {str(e)}",
        ) from e


@router.post(
    "/config/reset",
    response_model=APIResponse[dict[str, Any]],
    summary="Reset configuration to defaults",
)
async def reset_config(
    request: ConfigResetRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[dict[str, Any]]:
    """
    Reset configuration values to defaults.

    Args:
        request: Contains optional key path and save flag.
                 If path is None, resets all configuration.

    Returns:
        Confirmation of reset operation.
    """
    try:
        service = ConfigService()
        result = service.reset(request.path)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to reset configuration",
            )

        # Optionally save to disk
        if request.save:
            save_result = service.save()
            if not save_result.success:
                logger.warning(
                    f"Failed to save config after reset: {save_result.error}"
                )

        return APIResponse[dict[str, Any]](
            data={
                "reset": True,
                "path": request.path or "all",
                "saved": request.save,
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting config: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset configuration: {str(e)}",
        ) from e


@router.get(
    "/config/keys",
    response_model=APIResponse[ConfigKeysResponse],
    summary="List configuration keys",
)
async def list_config_keys(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    section: str | None = None,
) -> APIResponse[ConfigKeysResponse]:
    """
    List all configuration keys, optionally filtered by section.

    Args:
        section: Optional section name to filter keys.

    Returns:
        List of available configuration keys.
    """
    try:
        service = ConfigService()
        result = service.list_keys(section)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to list keys",
            )

        response_data = ConfigKeysResponse(
            keys=result.data or [],
            count=len(result.data or []),
        )

        return APIResponse[ConfigKeysResponse](data=response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing config keys: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list keys: {str(e)}",
        ) from e


@router.post(
    "/config/export",
    response_model=APIResponse[ConfigFileResponse],
    summary="Export configuration to file",
)
async def export_config(
    request: ConfigExportRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[ConfigFileResponse]:
    """
    Export current configuration to a file.

    Args:
        request: Contains output path and format (yaml or json).

    Returns:
        Information about the exported file.
    """
    try:
        if request.format not in ("yaml", "json"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Format must be 'yaml' or 'json'",
            )

        service = ConfigService()
        result = service.export_config(request.path, format=request.format)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to export configuration",
            )

        response_data = ConfigFileResponse(
            file_path=str(result.data),
            operation="export",
            format=request.format,
        )

        logger.info(f"Configuration exported to {result.data}")
        return APIResponse[ConfigFileResponse](data=response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting config to {request.path}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export configuration: {str(e)}",
        ) from e


@router.post(
    "/config/load",
    response_model=APIResponse[dict[str, Any]],
    summary="Load configuration from file",
)
async def load_config(
    request: ConfigLoadRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> APIResponse[dict[str, Any]]:
    """
    Load configuration from a file.

    Args:
        request: Contains input file path.

    Returns:
        Loaded configuration.
    """
    try:
        service = ConfigService()
        result = service.load(request.path)

        if not result.success:
            if "not found" in (result.error or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=result.error or f"File not found: {request.path}",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to load configuration",
            )

        logger.info(f"Configuration loaded from {request.path}")
        return APIResponse[dict[str, Any]](data=result.data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading config from {request.path}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load configuration: {str(e)}",
        ) from e


@router.post(
    "/config/save",
    response_model=APIResponse[ConfigFileResponse],
    summary="Save configuration to file",
)
async def save_config(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    request: ConfigSaveRequest | None = None,
) -> APIResponse[ConfigFileResponse]:
    """
    Save current configuration to file.

    Args:
        request: Optional path to save to (uses default if not provided).

    Returns:
        Information about the saved file.
    """
    try:
        service = ConfigService()
        save_path = request.path if request else None
        result = service.save(save_path)

        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error or "Failed to save configuration",
            )

        response_data = ConfigFileResponse(
            file_path=str(result.data),
            operation="save",
        )

        logger.info(f"Configuration saved to {result.data}")
        return APIResponse[ConfigFileResponse](data=response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving config: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save configuration: {str(e)}",
        ) from e
