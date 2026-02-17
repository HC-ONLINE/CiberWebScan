"""
Base service class and common types for CiberWebScan services.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generic, TypeVar

from ciberwebscan.config.loader import get_config
from ciberwebscan.export import CSVExporter, ExportError, JSONExporter, JSONLExporter

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _utc_now() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


class ServiceError(Exception):
    """Base exception for service errors."""

    def __init__(
        self, message: str, code: str = "SERVICE_ERROR", details: dict | None = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class ValidationError(ServiceError):
    """Input validation failed."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="VALIDATION_ERROR", details=details)


class ExecutionError(ServiceError):
    """Error during service execution."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="EXECUTION_ERROR", details=details)


@dataclass
class ServiceResult(Generic[T]):
    """
    Result wrapper for service operations.

    Provides consistent structure for all service responses including:
    - The actual result data
    - Execution metadata (timing, counts)
    - Export path if export was requested
    - Any warnings that occurred
    """

    success: bool
    data: T | None = None
    error: str | None = None
    error_code: str | None = None

    # Metadata
    started_at: datetime = field(default_factory=_utc_now)
    finished_at: datetime | None = None
    duration_seconds: float = 0.0

    # Export info
    exported: bool = False
    export_path: Path | None = None
    export_format: str | None = None

    # Warnings/info
    warnings: list[str] = field(default_factory=list)

    def finalize(self) -> ServiceResult[T]:
        """Mark the result as finished and calculate duration."""
        self.finished_at = _utc_now()
        self.duration_seconds = (self.finished_at - self.started_at).total_seconds()
        return self

    @classmethod
    def ok(cls, data: T, **kwargs: Any) -> ServiceResult[T]:
        """Create a successful result."""
        return cls(success=True, data=data, **kwargs)

    @classmethod
    def fail(cls, error: str, code: str = "ERROR", **kwargs: Any) -> ServiceResult[T]:
        """Create a failed result."""
        return cls(success=False, error=error, error_code=code, **kwargs)


class BaseService:
    """
    Base class for all services.

    Provides common functionality:
    - Logging setup
    - Export handling
    - Error handling patterns
    """

    def __init__(self, logger_name: str | None = None):
        """
        Initialize the base service.

        Args:
            logger_name: Name for the logger. Defaults to class name.
        """
        self.logger = logging.getLogger(logger_name or self.__class__.__name__)

    def _export_result(
        self,
        data: Any,
        output_path: Path | str,
        format: str = "json",
    ) -> tuple[bool, Path | None]:
        """
        Export result data to file.

        Args:
            data: Data to export (must be serializable).
            output_path: Path for output file.
            format: Export format ('json', 'jsonl', 'csv').

        Returns:
            Tuple of (success, actual_path).
        """
        path = Path(output_path)

        # Create parent directories if they don't exist
        path.parent.mkdir(parents=True, exist_ok=True)

        # Auto-detect format from extension if not specified
        if format == "auto":
            ext = path.suffix.lower()
            format = {".json": "json", ".jsonl": "jsonl", ".csv": "csv"}.get(
                ext, "json"
            )

        try:
            config = get_config()
            indent = 2 if config.export.pretty else None
            include_raw = config.export.include_raw_html
            buffer_size = config.export.buffer_size

            exporters = {
                "json": JSONExporter,
                "jsonl": JSONLExporter,
                "csv": CSVExporter,
            }

            if format not in exporters:
                self.logger.warning(f"Unknown format '{format}', using JSON")
                format = "json"

            exporter_class = exporters[format]

            # Build exporter with full config values
            if format == "json":
                exporter = exporter_class(
                    output_path=path, indent=indent, include_raw=include_raw
                )
            else:
                exporter = exporter_class(output_path=path, include_raw=include_raw)
            exporter.buffer_size = buffer_size

            # Export data
            if hasattr(data, "meta") and hasattr(data, "calculate_summary"):
                exporter.export_report(data)
            elif isinstance(data, list | tuple):
                with exporter:
                    for item in data:
                        exporter.write_item(item)
            else:
                with exporter:
                    exporter.write_item(data)

            self.logger.info(f"Exported to {path} ({format})")
            return True, path

        except ExportError as e:
            self.logger.error(f"Export failed: {e}")
            return False, None
        except Exception as e:
            self.logger.error(f"Unexpected export error: {e}")
            return False, None

    def _validate_url(self, url: str) -> str:
        """
        Validate and normalize URL.

        Args:
            url: URL to validate.

        Returns:
            Normalized URL.

        Raises:
            ValidationError: If URL is invalid.
        """
        if not url:
            raise ValidationError("URL is required")

        url = url.strip()

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # Basic validation
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValidationError(f"Invalid URL: {url}")
        except Exception as e:
            raise ValidationError(f"Invalid URL: {e}") from e

        return url
