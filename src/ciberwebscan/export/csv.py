"""
CSV exporter with streaming support for CiberWebScan.

Exports data to CSV format with support for:
- Streaming writes (row by row)
- Automatic column discovery from first item
- Flattening of nested structures
- Custom column mapping
"""

from __future__ import annotations

import csv
import logging
from collections.abc import Iterator, Sequence
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TextIO

from ciberwebscan.export.base import ExportWriteError, StreamingExporter

if TYPE_CHECKING:
    from ciberwebscan.export.models import AnalysisReport

logger = logging.getLogger(__name__)


def flatten_dict(
    data: dict[str, Any],
    parent_key: str = "",
    separator: str = ".",
    max_depth: int = 3,
) -> dict[str, Any]:
    """
    Flatten a nested dictionary for CSV export.

    Args:
        data: Dictionary to flatten.
        parent_key: Prefix for keys (used in recursion).
        separator: Separator between nested keys.
        max_depth: Maximum nesting depth to flatten.

    Returns:
        Flattened dictionary with dot-notation keys.

    Example:
        {"a": {"b": 1}} -> {"a.b": 1}
    """
    items: list[tuple[str, Any]] = []
    current_depth = parent_key.count(separator) if parent_key else 0

    for key, value in data.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key

        if isinstance(value, dict) and current_depth < max_depth:
            items.extend(flatten_dict(value, new_key, separator, max_depth).items())
        elif isinstance(value, list):
            # Convert list to string representation
            if value and isinstance(value[0], dict):
                # List of dicts - just count or first item
                items.append((f"{new_key}.count", len(value)))
            else:
                # Simple list - join values
                items.append((new_key, "; ".join(str(v) for v in value)))
        elif isinstance(value, datetime):
            items.append((new_key, value.isoformat()))
        elif isinstance(value, Enum):
            items.append((new_key, value.value))
        elif value is None:
            items.append((new_key, ""))
        else:
            items.append((new_key, value))

    return dict(items)


class CSVExporter(StreamingExporter):
    """
    CSV exporter with streaming support.

    Supports writing rows one by one with automatic header detection.
    Can flatten nested dictionaries to create columns.

    Example:
        with CSVExporter("output.csv") as exporter:
            exporter.write_item({"url": "...", "status": 200})
            exporter.write_item({"url": "...", "status": 404})
    """

    extension = ".csv"

    def __init__(
        self,
        output_path: str | Path | None = None,
        *,
        stream: TextIO | None = None,
        include_raw: bool = False,
        columns: Sequence[str] | None = None,
        flatten: bool = True,
        flatten_separator: str = ".",
        max_flatten_depth: int = 3,
        dialect: str = "excel",
        delimiter: str = ",",
        quoting: Literal[0, 1, 2, 3] = csv.QUOTE_MINIMAL,
    ) -> None:
        """
        Initialize CSV exporter.

        Args:
            output_path: Path to output file.
            stream: Open file-like object (alternative to output_path).
            include_raw: Include raw HTML/response data.
            columns: Explicit column list. If None, auto-detected from first item.
            flatten: Whether to flatten nested dictionaries.
            flatten_separator: Separator for flattened key names.
            max_flatten_depth: Maximum depth for flattening.
            dialect: CSV dialect to use.
            delimiter: Field delimiter.
            quoting: Quoting style (csv.QUOTE_* constants).
        """
        super().__init__(
            output_path=output_path,
            stream=stream,
            indent=None,
            include_raw=include_raw,
        )
        self.columns = list(columns) if columns else None
        self.flatten = flatten
        self.flatten_separator = flatten_separator
        self.max_flatten_depth = max_flatten_depth
        self.dialect = dialect
        self.delimiter = delimiter
        self.quoting: Literal[0, 1, 2, 3] = quoting
        self._writer: csv.DictWriter | None = None
        self._header_written = False

    def _get_writer(self) -> csv.DictWriter:
        """Get or create the CSV writer."""
        if self._writer is None:
            if self.columns is None:
                raise ExportWriteError(
                    "Columns not set. Either provide columns in constructor "
                    "or call write_header() first."
                )
            self._writer = csv.DictWriter(
                self.stream,
                fieldnames=self.columns,
                dialect=self.dialect,
                delimiter=self.delimiter,
                quoting=self.quoting,
                extrasaction="ignore",
            )
        return self._writer

    def write_header(self, meta: dict[str, Any] | None = None) -> None:
        """
        Write CSV header row.

        If columns were not provided in constructor, extracts them from meta.
        The meta parameter for CSV is expected to contain 'columns' key with
        the list of column names.

        Args:
            meta: Dictionary with optional 'columns' key for column names.
        """
        if self._started:
            raise ExportWriteError("Header already written")

        self._started = True

        if meta and "columns" in meta:
            self.columns = list(meta["columns"])

        if self.columns:
            writer = self._get_writer()
            writer.writeheader()
            self._header_written = True

    def write_item(self, item: Any) -> None:
        """
        Write a single row to the CSV.

        On first call, auto-detects columns from the item if not already set.

        Args:
            item: Item to write (dict, Pydantic model, etc.)
        """
        if self._finalized:
            raise ExportWriteError("Cannot write after finalization")

        try:
            data = self._serialize_item(item)

            # Flatten nested structures
            if self.flatten:
                data = flatten_dict(
                    data,
                    separator=self.flatten_separator,
                    max_depth=self.max_flatten_depth,
                )

            # Remove raw data if not requested
            if not self.include_raw:
                data.pop("raw_html", None)

            # Auto-detect columns from first item
            if self.columns is None:
                self.columns = list(data.keys())

            # Write header if not written
            if not self._header_written:
                self._started = True
                writer = self._get_writer()
                writer.writeheader()
                self._header_written = True
            else:
                writer = self._get_writer()

            # Write the row
            writer.writerow(data)
            self._items_written += 1

        except Exception as e:
            raise ExportWriteError(f"Failed to write item: {e}") from e

    def finalize(self) -> None:
        """Finalize the CSV export."""
        if self._finalized:
            return

        self.flush()
        self._finalized = True
        logger.debug(f"CSV export finalized: {self._items_written} rows written")

    def export_report(self, report: AnalysisReport) -> None:
        """
        Export analysis report to CSV.

        Since CSV is a flat format, this exports a summary row with key metrics.
        For detailed data, use JSON or JSONL format.

        Args:
            report: Complete analysis report to export.
        """
        if self._stream is None:
            if self.output_path is None:
                raise ExportWriteError("No output stream or path configured")
            with open(self.output_path, "w", encoding=self.encoding, newline="") as f:
                self._stream = f
                try:
                    # Calculate summary
                    report.calculate_summary()

                    # Build summary row
                    summary = {
                        "target_url": report.meta.target_url,
                        "timestamp": report.meta.timestamp.isoformat()
                        if report.meta.timestamp
                        else "",
                        "duration_seconds": report.meta.duration_seconds,
                        "version": report.meta.version,
                        "risk_score": report.risk_score,
                        "critical_findings": report.critical_findings,
                        "high_findings": report.high_findings,
                        "medium_findings": report.medium_findings,
                        "low_findings": report.low_findings,
                        "info_findings": report.info_findings,
                    }

                    # Add SSL info
                    if report.ssl:
                        summary["ssl_grade"] = report.ssl.grade or ""
                        summary["ssl_protocol"] = report.ssl.protocol_version
                        summary["is_https"] = report.ssl.is_https

                    # Add fingerprint summary
                    if report.fingerprint:
                        techs = [t.name for t in report.fingerprint.technologies[:5]]
                        summary["technologies"] = "; ".join(techs)
                        summary["server"] = report.fingerprint.server or ""
                        summary["framework"] = report.fingerprint.framework or ""

                    # Add CVE count
                    summary["cve_count"] = len(report.cves)

                    # Add attack summary
                    if report.attack:
                        summary["xss_findings"] = report.attack.xss_findings
                        summary["enumeration_findings"] = (
                            report.attack.enumeration_findings
                        )

                    # Set columns and write
                    if self.columns is None:
                        self.columns = list(summary.keys())

                    self.write_header()
                    self.write_item(summary)
                    self.finalize()

                    logger.info(
                        f"Report exported to CSV: {self.output_path or 'stream'}"
                    )
                finally:
                    self._stream = None
        else:
            try:
                # Calculate summary
                report.calculate_summary()

                # Build summary row
                summary = {
                    "target_url": report.meta.target_url,
                    "timestamp": report.meta.timestamp.isoformat()
                    if report.meta.timestamp
                    else "",
                    "duration_seconds": report.meta.duration_seconds,
                    "version": report.meta.version,
                    "risk_score": report.risk_score,
                    "critical_findings": report.critical_findings,
                    "high_findings": report.high_findings,
                    "medium_findings": report.medium_findings,
                    "low_findings": report.low_findings,
                    "info_findings": report.info_findings,
                }

                # Add SSL info
                if report.ssl:
                    summary["ssl_grade"] = report.ssl.grade or ""
                    summary["ssl_protocol"] = report.ssl.protocol_version
                    summary["is_https"] = report.ssl.is_https

                # Add fingerprint summary
                if report.fingerprint:
                    techs = [t.name for t in report.fingerprint.technologies[:5]]
                    summary["technologies"] = "; ".join(techs)
                    summary["server"] = report.fingerprint.server or ""
                    summary["framework"] = report.fingerprint.framework or ""

                # Add CVE count
                summary["cve_count"] = len(report.cves)

                # Add attack summary
                if report.attack:
                    summary["xss_findings"] = report.attack.xss_findings
                    summary["enumeration_findings"] = report.attack.enumeration_findings

                # Set columns and write
                if self.columns is None:
                    self.columns = list(summary.keys())

                self.write_header()
                self.write_item(summary)
                self.finalize()

                logger.info(f"Report exported to CSV: {self.output_path or 'stream'}")
            except Exception as e:
                raise ExportWriteError(f"Failed to export report: {e}") from e


def export_to_csv(
    items: Iterator[Any] | list[Any],
    output_path: str | Path,
    *,
    columns: Sequence[str] | None = None,
    flatten: bool = True,
) -> int:
    """
    Convenience function to export items to CSV file.

    Args:
        items: Iterable of items to export.
        output_path: Path to output file.
        columns: Explicit column list (auto-detected if None).
        flatten: Whether to flatten nested dictionaries.

    Returns:
        Number of rows written.
    """
    with CSVExporter(
        output_path=output_path,
        columns=columns,
        flatten=flatten,
    ) as exporter:
        for item in items:
            exporter.write_item(item)

        return exporter._items_written


def csv_to_dicts(
    path: str | Path,
    *,
    delimiter: str = ",",
) -> Iterator[dict[str, str]]:
    """
    Read a CSV file and yield each row as a dictionary.

    Args:
        path: Path to the CSV file.
        delimiter: Field delimiter.

    Yields:
        Dictionary for each row.
    """
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        yield from reader
