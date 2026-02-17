"""
JSON Lines exporter for CiberWebScan.

Exports data to JSON Lines format (.jsonl) where each line is a valid JSON object.
This format is ideal for streaming large datasets and log-style data.

Format specification: https://jsonlines.org/
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from ciberwebscan.export.base import ExportWriteError, StreamingExporter
from ciberwebscan.export.json import dumps

if TYPE_CHECKING:
    from ciberwebscan.export.models import AnalysisReport

logger = logging.getLogger(__name__)


class JSONLExporter(StreamingExporter):
    """
    JSON Lines exporter for streaming large datasets.

    Each line contains a complete JSON object, making it ideal for:
    - Large datasets that don't fit in memory
    - Append-only logging
    - Line-by-line processing
    - Streaming from/to pipelines

    Format:
        {"type": "meta", "version": "2.0", ...}
        {"type": "item", "url": "...", ...}
        {"type": "item", "url": "...", ...}

    Example:
        with JSONLExporter("output.jsonl") as exporter:
            exporter.write_header({"version": "2.0"})
            for result in scan_results:
                exporter.write_item(result)
    """

    extension = ".jsonl"

    def __init__(
        self,
        output_path: str | Path | None = None,
        *,
        stream: TextIO | None = None,
        include_raw: bool = False,
        include_type_field: bool = True,
    ) -> None:
        """
        Initialize JSON Lines exporter.

        Args:
            output_path: Path to output file.
            stream: Open file-like object (alternative to output_path).
            include_raw: Include raw HTML/response data.
            include_type_field: Add "type" field to each line for categorization.
        """
        # JSONL doesn't use indentation
        super().__init__(
            output_path=output_path,
            stream=stream,
            indent=None,
            include_raw=include_raw,
        )
        self.include_type_field = include_type_field

    def write_header(self, meta: dict[str, Any] | None = None) -> None:
        """
        Write metadata as the first line.

        Args:
            meta: Metadata dictionary. Will be written as first line with type="meta".
        """
        if self._started:
            raise ExportWriteError("Header already written")

        self._started = True

        if meta:
            if self.include_type_field:
                meta = {"type": "meta", **meta}
            self._write_line(meta)

    def write_item(self, item: Any, item_type: str = "item") -> None:
        """
        Write a single item as a JSON line.

        Args:
            item: Item to write (dict, Pydantic model, etc.)
            item_type: Type label for the item (default: "item").
        """
        if self._finalized:
            raise ExportWriteError("Cannot write after finalization")

        if not self._started:
            self._started = True

        try:
            data = self._serialize_item(item)

            if self.include_type_field and "type" not in data:
                data = {"type": item_type, **data}

            self._write_line(data)
            self._items_written += 1

        except Exception as e:
            raise ExportWriteError(f"Failed to write item: {e}") from e

    def _write_line(self, data: dict[str, Any]) -> None:
        """Write a single JSON line."""
        line = dumps(data, indent=None)
        self.stream.write(line)
        self.stream.write("\n")

    def finalize(self) -> None:
        """Finalize the export (no-op for JSONL, each line is complete)."""
        if self._finalized:
            return

        self.flush()
        self._finalized = True
        logger.debug(f"JSONL export finalized: {self._items_written} items written")

    def export_report(self, report: AnalysisReport) -> None:
        """
        Export a complete analysis report to JSON Lines.

        Each section of the report is written as a separate line.

        Args:
            report: Complete analysis report to export.
        """
        # If no external stream provided, open file using context manager
        if self._stream is None:
            if self.output_path is None:
                raise ExportWriteError("No output stream or path configured")
            with open(self.output_path, "w", encoding=self.encoding) as f:
                self._stream = f
                try:
                    # Write metadata
                    meta_data = self._serialize_item(report.meta)
                    self.write_header(meta_data)

                    # Write scrape result
                    if report.scrape:
                        scrape_data = self._serialize_item(report.scrape)
                        self.write_item(scrape_data, item_type="scrape")

                    # Write fingerprint result
                    if report.fingerprint:
                        self.write_item(
                            self._serialize_item(report.fingerprint),
                            item_type="fingerprint",
                        )

                    # Write SSL result
                    if report.ssl:
                        self.write_item(
                            self._serialize_item(report.ssl), item_type="ssl"
                        )

                    # Write headers result
                    if report.headers:
                        self.write_item(
                            self._serialize_item(report.headers), item_type="headers"
                        )

                    # Write CVEs (each as separate line)
                    for cve in report.cves:
                        self.write_item(self._serialize_item(cve), item_type="cve")

                    # Write attack result
                    if report.attack:
                        self.write_item(
                            self._serialize_item(report.attack), item_type="attack"
                        )

                    # Write summary
                    report.calculate_summary()
                    summary = {
                        "risk_score": report.risk_score,
                        "critical_findings": report.critical_findings,
                        "high_findings": report.high_findings,
                        "medium_findings": report.medium_findings,
                        "low_findings": report.low_findings,
                        "info_findings": report.info_findings,
                    }
                    self.write_item(summary, item_type="summary")

                    self.finalize()
                    logger.info(
                        f"Report exported to JSONL: {self.output_path or 'stream'}"
                    )

                finally:
                    self._stream = None
        else:
            # Use existing stream passed by caller
            # Write metadata
            meta_data = self._serialize_item(report.meta)
            self.write_header(meta_data)

            # Write scrape result
            if report.scrape:
                scrape_data = self._serialize_item(report.scrape)
                self.write_item(scrape_data, item_type="scrape")

            # Write fingerprint result
            if report.fingerprint:
                self.write_item(
                    self._serialize_item(report.fingerprint), item_type="fingerprint"
                )

            # Write SSL result
            if report.ssl:
                self.write_item(self._serialize_item(report.ssl), item_type="ssl")

            # Write headers result
            if report.headers:
                self.write_item(
                    self._serialize_item(report.headers), item_type="headers"
                )

            # Write CVEs (each as separate line)
            for cve in report.cves:
                self.write_item(self._serialize_item(cve), item_type="cve")

            # Write attack result
            if report.attack:
                self.write_item(self._serialize_item(report.attack), item_type="attack")

            # Write summary
            report.calculate_summary()
            summary = {
                "risk_score": report.risk_score,
                "critical_findings": report.critical_findings,
                "high_findings": report.high_findings,
                "medium_findings": report.medium_findings,
                "low_findings": report.low_findings,
                "info_findings": report.info_findings,
            }
            self.write_item(summary, item_type="summary")

            self.finalize()
            logger.info(f"Report exported to JSONL: {self.output_path or 'stream'}")


def read_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """
    Read a JSON Lines file and yield each line as a dictionary.

    Args:
        path: Path to the JSONL file.

    Yields:
        Dictionary for each line.
    """
    import json

    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON on line {line_num}: {e}")
                continue


def export_to_jsonl(
    items: Iterator[Any] | list[Any],
    output_path: str | Path,
    *,
    meta: dict[str, Any] | None = None,
    include_raw: bool = False,
) -> int:
    """
    Convenience function to export items to JSON Lines file.

    Args:
        items: Iterable of items to export.
        output_path: Path to output file.
        meta: Optional metadata to write as first line.
        include_raw: Include raw HTML/response data.

    Returns:
        Number of items written.
    """
    with JSONLExporter(output_path=output_path, include_raw=include_raw) as exporter:
        if meta:
            exporter.write_header(meta)

        for item in items:
            exporter.write_item(item)

        return exporter._items_written
