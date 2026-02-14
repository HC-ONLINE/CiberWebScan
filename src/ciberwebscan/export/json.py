"""
JSON exporter with streaming support for CiberWebScan.

Exports data to JSON format with optional streaming for large datasets.
Uses orjson for high-performance serialization when available.
"""

from __future__ import annotations

import logging
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

import orjson

from ciberwebscan.config.loader import get_config
from ciberwebscan.export.base import ExportWriteError, StreamingExporter

if TYPE_CHECKING:
    from ciberwebscan.export.models import AnalysisReport

logger = logging.getLogger(__name__)


def _json_serializer(obj: Any) -> Any:
    """
    Custom JSON serializer for objects not serializable by default.

    Handles datetime, Enum, Path, Pydantic models, and dataclasses.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "model_dump"):
        # Pydantic v2
        return obj.model_dump()
    if hasattr(obj, "dict"):
        # Pydantic v1
        return obj.dict()
    if hasattr(obj, "__dataclass_fields__"):
        from dataclasses import asdict

        return asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def dumps(
    data: Any,
    *,
    indent: int | None = None,
    ensure_ascii: bool = False,
) -> str:
    """
    Serialize data to JSON string.

    Uses orjson if available for better performance.

    Args:
        data: Data to serialize.
        indent: Indentation level (None for compact).
        ensure_ascii: Whether to escape non-ASCII characters.

    Returns:
        JSON string.
    """
    opts = orjson.OPT_NON_STR_KEYS
    if indent:
        opts |= orjson.OPT_INDENT_2
    result = orjson.dumps(data, default=_json_serializer, option=opts)
    return result.decode("utf-8")


def dump(
    data: Any,
    fp: TextIO,
    *,
    indent: int | None = None,
    ensure_ascii: bool = False,
) -> None:
    """
    Serialize data to JSON and write to file.

    Args:
        data: Data to serialize.
        fp: File-like object to write to.
        indent: Indentation level (None for compact).
        ensure_ascii: Whether to escape non-ASCII characters.
    """
    fp.write(dumps(data, indent=indent, ensure_ascii=ensure_ascii))


class JSONExporter(StreamingExporter):
    """
    JSON exporter with streaming support.

    Supports two modes:
    1. Streaming: Write items one by one to an array
    2. Batch: Export complete report at once

    Streaming mode writes a valid JSON object with structure:
    {
        "meta": {...},
        "items": [
            {...},
            {...}
        ]
    }

    Example (streaming):
        with JSONExporter("output.json", indent=2) as exporter:
            exporter.write_header({"version": "2.0", "timestamp": "..."})
            for item in results:
                exporter.write_item(item)

    Example (batch):
        exporter = JSONExporter("output.json", indent=2)
        exporter.export_report(report)
    """

    extension = ".json"

    def __init__(
        self,
        output_path: str | Path | None = None,
        *,
        stream: TextIO | None = None,
        indent: int | None = 2,
        include_raw: bool = False,
        items_key: str = "items",
    ) -> None:
        """
        Initialize JSON exporter.

        Args:
            output_path: Path to output file.
            stream: Open file-like object (alternative to output_path).
            indent: Indentation level (default: 2, None for compact).
            include_raw: Include raw HTML/response data.
            items_key: Key name for the items array in streaming mode.
        """
        super().__init__(
            output_path=output_path,
            stream=stream,
            indent=indent,
            include_raw=include_raw,
        )
        self.items_key = items_key
        self._in_array = False

    def write_header(self, meta: dict[str, Any] | None = None) -> None:
        """
        Write JSON header and begin items array.

        Args:
            meta: Metadata to include at the top level.
        """
        if self._started:
            raise ExportWriteError("Header already written")

        self._started = True
        stream = self.stream

        # Start the JSON object
        if self.indent:
            stream.write("{\n")
            indent_str = " " * self.indent

            # Write metadata if provided
            if meta:
                meta_json = dumps(meta, indent=self.indent)
                # Indent each line of meta
                meta_lines = meta_json.split("\n")
                stream.write(f'{indent_str}"meta": ')
                for i, line in enumerate(meta_lines):
                    if i > 0:
                        stream.write(indent_str)
                    stream.write(line)
                    if i < len(meta_lines) - 1:
                        stream.write("\n")
                stream.write(",\n")

            # Start items array
            stream.write(f'{indent_str}"{self.items_key}": [\n')
        else:
            stream.write("{")
            if meta:
                stream.write(f'"meta":{dumps(meta)},')
            stream.write(f'"{self.items_key}":[')

        self._in_array = True

    def write_item(self, item: Any) -> None:
        """
        Write a single item to the JSON array.

        Args:
            item: Item to write (dict, Pydantic model, etc.)
        """
        if not self._started:
            # Auto-start with empty header
            self.write_header()

        if self._finalized:
            raise ExportWriteError("Cannot write after finalization")

        try:
            data = self._serialize_item(item)
            item_json = dumps(data, indent=self.indent)

            stream = self.stream

            # Add comma before item (except first)
            if self._items_written > 0:
                stream.write(",")
                if self.indent:
                    stream.write("\n")

            # Write the item with proper indentation
            if self.indent:
                indent_str = " " * (self.indent * 2)
                lines = item_json.split("\n")
                for i, line in enumerate(lines):
                    stream.write(f"{indent_str}{line}")
                    if i < len(lines) - 1:
                        stream.write("\n")
            else:
                stream.write(item_json)

            self._items_written += 1

        except Exception as e:
            raise ExportWriteError(f"Failed to write item: {e}") from e

    def finalize(self) -> None:
        """Close the JSON array and object."""
        if self._finalized:
            return

        stream = self.stream

        if self._in_array:
            # Close items array
            if self.indent:
                stream.write("\n")
                stream.write(" " * self.indent + "]\n")
            else:
                stream.write("]")

        # Close root object
        stream.write("}")

        if self.indent:
            stream.write("\n")

        self._finalized = True
        logger.debug(f"JSON export finalized: {self._items_written} items written")

    def export_report(self, report: AnalysisReport) -> None:
        """
        Export a complete analysis report to JSON.

        This method writes the entire report at once (batch mode).

        Args:
            report: Complete analysis report to export.
        """
        if self._started:
            raise ExportWriteError(
                "Cannot use export_report after streaming writes. "
                "Use either streaming (write_header/write_item) or batch (export_report)."
            )

        try:
            # Serialize the report
            data = self._serialize_item(report)

            # Remove raw data if not requested
            if not self.include_raw and "scrape" in data and data["scrape"]:
                data["scrape"].pop("raw_html", None)

            # Calculate summary if not done
            if hasattr(report, "calculate_summary"):
                report.calculate_summary()
                data = self._serialize_item(report)

            # Write to stream or file
            if self._stream:
                dump(data, self._stream, indent=self.indent)
                self._finalized = True
            elif self.output_path:
                with open(self.output_path, "w", encoding=self.encoding) as f:
                    dump(data, f, indent=self.indent)
                self._finalized = True
            else:
                raise ExportWriteError("No output stream or path configured")

            logger.info(f"Report exported to JSON: {self.output_path or 'stream'}")

        except Exception as e:
            raise ExportWriteError(f"Failed to export report: {e}") from e


def export_to_json(
    data: Any,
    output_path: str | Path,
    *,
    indent: int | None = None,
    include_raw: bool = False,
) -> None:
    """
    Convenience function to export data to JSON file.

    Args:
        data: Data to export (dict, Pydantic model, AnalysisReport, etc.)
        output_path: Path to output file.
        indent: Indentation level (None for compact, uses config.export.pretty if None).
        include_raw: Include raw HTML/response data.
    """
    if indent is None:
        config = get_config()
        indent = 2 if config.export.pretty else None
    exporter = JSONExporter(
        output_path=output_path,
        indent=indent,
        include_raw=include_raw,
    )

    # Check if it's an AnalysisReport
    if hasattr(data, "meta") and hasattr(data, "scrape"):
        exporter.export_report(data)
    else:
        # Generic export
        path = Path(output_path)
        with open(path, "w", encoding="utf-8") as f:
            if hasattr(data, "model_dump"):
                dump(data.model_dump(), f, indent=indent)
            elif hasattr(data, "dict"):
                dump(data.dict(), f, indent=indent)
            else:
                dump(data, f, indent=indent)
