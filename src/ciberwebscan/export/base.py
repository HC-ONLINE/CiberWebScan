"""
Base exporter classes for CiberWebScan.

Provides abstract base class and common utilities for all export formats.
Designed for streaming to handle large datasets efficiently.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from ciberwebscan.export.models import AnalysisReport

logger = logging.getLogger(__name__)


class ExportError(Exception):
    """Base exception for export errors."""

    pass


class ExportWriteError(ExportError):
    """Error writing to export file."""

    pass


class ExportValidationError(ExportError):
    """Error validating data for export."""

    pass


class BaseExporter(ABC):
    """
    Abstract base class for all exporters.

    Supports both streaming and batch export modes:
    - Streaming: Write items one by one without loading all in memory
    - Batch: Export complete report at once (for smaller datasets)

    Subclasses must implement:
    - write_item(): Write a single item to the stream
    - finalize(): Complete the export (close brackets, write footers, etc.)

    Example usage (streaming):
        with JSONExporter("output.json") as exporter:
            exporter.write_header(meta)
            for item in results:
                exporter.write_item(item)

    Example usage (batch):
        exporter = JSONExporter("output.json")
        exporter.export_report(analysis_report)
    """

    # File extension for this format
    extension: str = ""

    # Default encoding
    encoding: str = "utf-8"

    def __init__(
        self,
        output_path: str | Path | None = None,
        *,
        stream: TextIO | None = None,
        indent: int | None = None,
        include_raw: bool = False,
    ) -> None:
        """
        Initialize the exporter.

        Args:
            output_path: Path to output file. If None, must provide stream.
            stream: Open file-like object to write to. Takes precedence over output_path.
            indent: Indentation level for pretty printing (None for compact).
            include_raw: Whether to include raw HTML/response data.
        """
        self.output_path = Path(output_path) if output_path else None
        self._stream = stream
        self._owns_stream = False
        self.indent = indent
        self.include_raw = include_raw
        self._items_written = 0
        self._started = False
        self._finalized = False

    @property
    def stream(self) -> TextIO:
        """Get the output stream, opening if necessary."""
        if self._stream is None:
            raise ExportError("No output stream available. Use context manager.")
        return self._stream

    def __enter__(self) -> BaseExporter:
        """Open the exporter for streaming writes."""
        if self._stream is None:
            if self.output_path is None:
                raise ExportError("No output path or stream provided.")
            self._stream = open(self.output_path, "w", encoding=self.encoding)
            self._owns_stream = True
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close the exporter and finalize output."""
        try:
            if not self._finalized and self._started:
                self.finalize()
        finally:
            if self._owns_stream and self._stream:
                self._stream.close()
                self._stream = None
                self._owns_stream = False

    @abstractmethod
    def write_header(self, meta: dict[str, Any] | None = None) -> None:
        """
        Write the export header/opening.

        Args:
            meta: Optional metadata to include in header.
        """
        pass

    @abstractmethod
    def write_item(self, item: Any) -> None:
        """
        Write a single item to the export.

        Args:
            item: The item to write (dict, Pydantic model, etc.)
        """
        pass

    @abstractmethod
    def finalize(self) -> None:
        """
        Finalize the export (close brackets, write footers, etc.).

        Called automatically when exiting context manager.
        """
        pass

    @abstractmethod
    def export_report(self, report: AnalysisReport) -> None:
        """
        Export a complete analysis report.

        Args:
            report: The complete analysis report to export.
        """
        pass

    def _serialize_item(self, item: Any) -> dict[str, Any]:
        """
        Serialize an item to a dictionary.

        Handles Pydantic models, dataclasses, and plain dicts.
        Strips ``raw_html`` when *include_raw* is False.
        """
        if hasattr(item, "model_dump"):
            # Pydantic v2
            data = item.model_dump(exclude_none=not self.include_raw)
        elif hasattr(item, "dict"):
            # Pydantic v1
            data = item.dict(exclude_none=not self.include_raw)
        elif hasattr(item, "__dataclass_fields__"):
            # Dataclass
            from dataclasses import asdict

            data = asdict(item)
        elif isinstance(item, dict):
            data = dict(item)  # shallow copy to avoid mutating caller's dict
        else:
            raise ExportValidationError(
                f"Cannot serialize item of type {type(item).__name__}"
            )

        if not self.include_raw:
            data.pop("raw_html", None)

        return data

    def _format_datetime(self, dt: datetime | None) -> str | None:
        """Format datetime to ISO 8601 string."""
        if dt is None:
            return None
        return dt.isoformat()


class StreamingExporter(BaseExporter):
    """
    Base class for exporters that support true streaming.

    Writes items as they come without buffering the entire dataset.
    """

    def __init__(
        self,
        output_path: str | Path | None = None,
        *,
        stream: TextIO | None = None,
        indent: int | None = None,
        include_raw: bool = False,
        buffer_size: int = 8192,
    ) -> None:
        """
        Initialize streaming exporter.

        Args:
            buffer_size: Write buffer size in bytes.
        """
        super().__init__(
            output_path=output_path,
            stream=stream,
            indent=indent,
            include_raw=include_raw,
        )
        self.buffer_size = buffer_size

    def flush(self) -> None:
        """Flush the output buffer to disk."""
        if self._stream:
            self._stream.flush()


@contextmanager
def export_to_file(
    path: str | Path,
    format: str = "json",
    **kwargs: Any,
) -> Generator[BaseExporter, None, None]:
    """
    Context manager to export data to a file.

    Args:
        path: Output file path.
        format: Export format ('json', 'jsonl', 'csv').
        **kwargs: Additional arguments passed to exporter.

    Yields:
        Configured exporter instance.

    Example:
        with export_to_file("results.json", format="json") as exporter:
            exporter.write_header({"version": "2.0"})
            for result in scan_results:
                exporter.write_item(result)
    """
    from ciberwebscan.export.csv import CSVExporter
    from ciberwebscan.export.json import JSONExporter
    from ciberwebscan.export.jsonl import JSONLExporter

    exporters = {
        "json": JSONExporter,
        "jsonl": JSONLExporter,
        "csv": CSVExporter,
    }

    format_lower = format.lower()
    if format_lower not in exporters:
        raise ExportError(
            f"Unknown export format: {format}. Use: {list(exporters.keys())}"
        )

    exporter_class = exporters[format_lower]
    exporter = exporter_class(output_path=path, **kwargs)

    with exporter as exp:
        yield exp


def get_exporter(
    format: str,
    output_path: str | Path | None = None,
    **kwargs: Any,
) -> BaseExporter:
    """
    Factory function to get an exporter instance.

    Args:
        format: Export format ('json', 'jsonl', 'csv').
        output_path: Optional output file path.
        **kwargs: Additional arguments for the exporter.

    Returns:
        Configured exporter instance (not opened).
    """
    from ciberwebscan.export.csv import CSVExporter
    from ciberwebscan.export.json import JSONExporter
    from ciberwebscan.export.jsonl import JSONLExporter

    exporters = {
        "json": JSONExporter,
        "jsonl": JSONLExporter,
        "csv": CSVExporter,
    }

    format_lower = format.lower()
    if format_lower not in exporters:
        raise ExportError(
            f"Unknown export format: {format}. Use: {list(exporters.keys())}"
        )

    return exporters[format_lower](output_path=output_path, **kwargs)
