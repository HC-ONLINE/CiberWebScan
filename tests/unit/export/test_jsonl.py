"""
Tests for JSON Lines exporter.
"""

from __future__ import annotations

import json
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ciberwebscan.export.base import ExportWriteError
from ciberwebscan.export.jsonl import (
    JSONLExporter,
    export_to_jsonl,
    read_jsonl,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_items():
    """Sample items for testing."""
    return [
        {"url": "https://example.com/1", "status": 200},
        {"url": "https://example.com/2", "status": 404},
        {"url": "https://example.com/3", "status": 500},
    ]


@pytest.fixture
def mock_report():
    """Create a mock AnalysisReport."""
    report = MagicMock()

    # Meta
    report.meta = MagicMock()
    report.meta.target_url = "https://example.com"
    report.meta.timestamp = datetime(2025, 1, 15, 10, 0, 0)
    report.meta.duration_seconds = 5.5
    report.meta.version = "2.0.0"

    # Components
    report.scrape = MagicMock()
    report.scrape.url = "https://example.com"
    report.fingerprint = MagicMock()
    report.fingerprint.technologies = []
    report.ssl = MagicMock()
    report.ssl.grade = "A"
    report.headers = MagicMock()
    report.cves = []
    report.attack = None

    # Summary
    report.risk_score = 25
    report.critical_findings = 0
    report.high_findings = 1
    report.medium_findings = 2
    report.low_findings = 0
    report.info_findings = 3

    return report


# =============================================================================
# JSONLExporter Tests
# =============================================================================


class TestJSONLExporter:
    """Tests for JSONLExporter class."""

    def test_init_defaults(self):
        """Test default initialization."""
        exporter = JSONLExporter()

        assert exporter.indent is None  # JSONL doesn't use indent
        assert exporter.include_type_field is True
        assert exporter.extension == ".jsonl"

    def test_init_no_type_field(self):
        """Test initialization without type field."""
        exporter = JSONLExporter(include_type_field=False)

        assert exporter.include_type_field is False


class TestJSONLExporterStreaming:
    """Tests for streaming mode."""

    def test_write_header(self):
        """Test writing header as first line."""
        stream = StringIO()
        meta = {"version": "2.0", "timestamp": "2025-01-15"}

        with JSONLExporter(stream=stream) as exporter:
            exporter.write_header(meta)

        stream.seek(0)
        line = json.loads(stream.readline())
        assert line["type"] == "meta"
        assert line["version"] == "2.0"

    def test_write_header_twice_raises(self):
        """Test writing header twice raises error."""
        stream = StringIO()

        with JSONLExporter(stream=stream) as exporter:
            exporter.write_header({"version": "1.0"})

            with pytest.raises(ExportWriteError, match="Header already written"):
                exporter.write_header({"version": "2.0"})

    def test_write_single_item(self):
        """Test writing a single item."""
        stream = StringIO()
        item = {"url": "https://example.com", "status": 200}

        with JSONLExporter(stream=stream) as exporter:
            exporter.write_item(item)

        stream.seek(0)
        line = json.loads(stream.readline())
        assert line["type"] == "item"
        assert line["url"] == "https://example.com"

    def test_write_multiple_items(self, sample_items):
        """Test writing multiple items."""
        stream = StringIO()

        with JSONLExporter(stream=stream) as exporter:
            for item in sample_items:
                exporter.write_item(item)

        stream.seek(0)
        lines = [json.loads(line) for line in stream.readlines()]
        assert len(lines) == 3
        assert all(line["type"] == "item" for line in lines)

    def test_write_item_custom_type(self):
        """Test writing item with custom type."""
        stream = StringIO()

        with JSONLExporter(stream=stream) as exporter:
            exporter.write_item({"data": "test"}, item_type="custom")

        stream.seek(0)
        line = json.loads(stream.readline())
        assert line["type"] == "custom"

    def test_write_item_no_type_field(self):
        """Test writing item without type field."""
        stream = StringIO()

        with JSONLExporter(stream=stream, include_type_field=False) as exporter:
            exporter.write_item({"url": "https://example.com"})

        stream.seek(0)
        line = json.loads(stream.readline())
        assert "type" not in line
        assert line["url"] == "https://example.com"

    def test_write_item_preserves_existing_type(self):
        """Test writing item with existing type field preserves it."""
        stream = StringIO()

        with JSONLExporter(stream=stream) as exporter:
            exporter.write_item({"type": "existing", "data": "test"})

        stream.seek(0)
        line = json.loads(stream.readline())
        assert line["type"] == "existing"  # Original type preserved

    def test_write_after_finalize_raises(self):
        """Test writing after finalize raises error."""
        stream = StringIO()

        exporter = JSONLExporter(stream=stream)
        exporter._finalized = True

        with pytest.raises(ExportWriteError, match="Cannot write after finalization"):
            exporter.write_item({"test": "data"})

    def test_each_line_is_valid_json(self, sample_items):
        """Test each line is independently valid JSON."""
        stream = StringIO()

        with JSONLExporter(stream=stream) as exporter:
            exporter.write_header({"version": "2.0"})
            for item in sample_items:
                exporter.write_item(item)

        stream.seek(0)
        for line in stream.readlines():
            # Each line should parse independently
            parsed = json.loads(line.strip())
            assert isinstance(parsed, dict)

    def test_items_written_count(self, sample_items):
        """Test items_written counter."""
        stream = StringIO()

        with JSONLExporter(stream=stream) as exporter:
            for item in sample_items:
                exporter.write_item(item)

            assert exporter._items_written == 3


class TestJSONLExporterBatch:
    """Tests for batch mode (export_report)."""

    def test_export_report_to_file(self, tmp_path: Path, mock_report):
        """Test exporting report to file."""
        output = tmp_path / "report.jsonl"

        # Mock the serialize methods
        mock_report.meta.model_dump = MagicMock(
            return_value={
                "target_url": "https://example.com",
                "version": "2.0.0",
            }
        )
        mock_report.scrape.model_dump = MagicMock(
            return_value={
                "url": "https://example.com",
            }
        )
        mock_report.fingerprint.model_dump = MagicMock(
            return_value={
                "technologies": [],
            }
        )
        mock_report.ssl.model_dump = MagicMock(
            return_value={
                "grade": "A",
            }
        )
        mock_report.headers.model_dump = MagicMock(
            return_value={
                "findings": [],
            }
        )

        exporter = JSONLExporter(output_path=output)
        exporter.export_report(mock_report)

        assert output.exists()
        lines = output.read_text().strip().split("\n")
        # Should have: meta, scrape, fingerprint, ssl, headers, summary
        assert len(lines) >= 5

    def test_export_report_line_types(self, tmp_path: Path, mock_report):
        """Test exported lines have correct types."""
        output = tmp_path / "report.jsonl"

        # Setup mocks
        mock_report.meta.model_dump = MagicMock(return_value={"version": "2.0"})
        mock_report.scrape.model_dump = MagicMock(return_value={"url": "test"})
        mock_report.fingerprint.model_dump = MagicMock(return_value={})
        mock_report.ssl.model_dump = MagicMock(return_value={})
        mock_report.headers.model_dump = MagicMock(return_value={})

        exporter = JSONLExporter(output_path=output)
        exporter.export_report(mock_report)

        lines = [json.loads(line) for line in output.read_text().strip().split("\n")]
        types = [line["type"] for line in lines]

        assert "meta" in types
        assert "scrape" in types
        assert "summary" in types


class TestReadJsonl:
    """Tests for read_jsonl function."""

    def test_read_jsonl_file(self, tmp_path: Path):
        """Test reading JSONL file."""
        jsonl_file = tmp_path / "test.jsonl"
        jsonl_file.write_text(
            '{"id": 1, "name": "first"}\n'
            '{"id": 2, "name": "second"}\n'
            '{"id": 3, "name": "third"}\n'
        )

        items = list(read_jsonl(jsonl_file))

        assert len(items) == 3
        assert items[0]["id"] == 1
        assert items[2]["name"] == "third"

    def test_read_jsonl_skips_empty_lines(self, tmp_path: Path):
        """Test reading JSONL skips empty lines."""
        jsonl_file = tmp_path / "test.jsonl"
        jsonl_file.write_text('{"id": 1}\n\n{"id": 2}\n   \n{"id": 3}\n')

        items = list(read_jsonl(jsonl_file))

        assert len(items) == 3

    def test_read_jsonl_handles_invalid_json(self, tmp_path: Path, caplog):
        """Test reading JSONL handles invalid JSON gracefully."""
        jsonl_file = tmp_path / "test.jsonl"
        jsonl_file.write_text('{"id": 1}\ninvalid json line\n{"id": 2}\n')

        items = list(read_jsonl(jsonl_file))

        assert len(items) == 2
        assert "Invalid JSON" in caplog.text


class TestExportToJsonl:
    """Tests for export_to_jsonl convenience function."""

    def test_export_list_to_jsonl(self, tmp_path: Path, sample_items):
        """Test exporting list of items."""
        output = tmp_path / "test.jsonl"

        count = export_to_jsonl(sample_items, output)

        assert count == 3
        assert output.exists()

        lines = output.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_export_with_meta(self, tmp_path: Path, sample_items):
        """Test exporting with metadata."""
        output = tmp_path / "test.jsonl"

        export_to_jsonl(sample_items, output, meta={"version": "2.0"})

        lines = [json.loads(line) for line in output.read_text().strip().split("\n")]
        assert lines[0]["type"] == "meta"
        assert lines[0]["version"] == "2.0"

    def test_export_generator(self, tmp_path: Path):
        """Test exporting from generator."""
        output = tmp_path / "test.jsonl"

        def item_generator():
            for i in range(5):
                yield {"index": i}

        count = export_to_jsonl(item_generator(), output)

        assert count == 5


class TestJSONLExporterFileOutput:
    """Tests for file output."""

    def test_output_to_file(self, tmp_path: Path, sample_items):
        """Test complete output to file."""
        output = tmp_path / "results.jsonl"

        with JSONLExporter(output_path=output) as exporter:
            exporter.write_header({"version": "2.0"})
            for item in sample_items:
                exporter.write_item(item)

        assert output.exists()
        lines = output.read_text().strip().split("\n")
        assert len(lines) == 4  # 1 meta + 3 items

    def test_finalize_is_idempotent(self, tmp_path: Path):
        """Test finalize can be called multiple times."""
        output = tmp_path / "test.jsonl"

        with JSONLExporter(output_path=output) as exporter:
            exporter.write_item({"test": 1})
            exporter.finalize()
            exporter.finalize()  # Should not raise

        lines = output.read_text().strip().split("\n")
        assert len(lines) == 1
