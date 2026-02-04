"""
Tests for CSV exporter.
"""

from __future__ import annotations

import csv
from datetime import datetime
from enum import Enum
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ciberwebscan.export.base import ExportWriteError
from ciberwebscan.export.csv import (
    CSVExporter,
    csv_to_dicts,
    export_to_csv,
    flatten_dict,
)

# =============================================================================
# Test Fixtures
# =============================================================================


class Status(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


@pytest.fixture
def sample_items():
    """Sample items for testing."""
    return [
        {"url": "https://example.com/1", "status": 200, "title": "Page 1"},
        {"url": "https://example.com/2", "status": 404, "title": "Page 2"},
        {"url": "https://example.com/3", "status": 500, "title": "Page 3"},
    ]


@pytest.fixture
def nested_item():
    """Sample nested item for flattening tests."""
    return {
        "url": "https://example.com",
        "meta": {
            "title": "Example",
            "description": "A test page",
        },
        "ssl": {
            "grade": "A+",
            "protocol": "TLS 1.3",
        },
        "tags": ["security", "test"],
    }


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

    # SSL
    report.ssl = MagicMock()
    report.ssl.grade = "A"
    report.ssl.protocol_version = "TLS 1.3"
    report.ssl.is_https = True

    # Fingerprint
    report.fingerprint = MagicMock()
    tech1 = MagicMock()
    tech1.name = "nginx"
    tech2 = MagicMock()
    tech2.name = "Python"
    report.fingerprint.technologies = [tech1, tech2]
    report.fingerprint.server = "nginx/1.18"
    report.fingerprint.framework = "FastAPI"

    # CVEs
    report.cves = [MagicMock(), MagicMock()]  # 2 CVEs

    # Attack
    report.attack = MagicMock()
    report.attack.xss_findings = 1
    report.attack.enumeration_findings = 3

    # Summary
    report.risk_score = 35
    report.critical_findings = 0
    report.high_findings = 2
    report.medium_findings = 3
    report.low_findings = 1
    report.info_findings = 5

    return report


# =============================================================================
# flatten_dict Tests
# =============================================================================


class TestFlattenDict:
    """Tests for flatten_dict function."""

    def test_flatten_simple_dict(self):
        """Test flattening simple dict (no nesting)."""
        data = {"key": "value", "number": 42}

        result = flatten_dict(data)

        assert result == {"key": "value", "number": 42}

    def test_flatten_nested_dict(self):
        """Test flattening nested dict."""
        data = {
            "name": "test",
            "config": {
                "timeout": 30,
                "retries": 3,
            },
        }

        result = flatten_dict(data)

        assert result == {
            "name": "test",
            "config.timeout": 30,
            "config.retries": 3,
        }

    def test_flatten_deeply_nested(self):
        """Test flattening deeply nested dict."""
        data = {"a": {"b": {"c": "deep"}}}

        result = flatten_dict(data)

        assert result == {"a.b.c": "deep"}

    def test_flatten_max_depth(self):
        """Test flatten respects max_depth."""
        data = {"a": {"b": {"c": "value"}}}

        # With max_depth=0, should not flatten at all
        result = flatten_dict(data, max_depth=0)

        assert "a" in result
        assert isinstance(result["a"], dict)

    def test_flatten_list_simple(self):
        """Test flattening list of simple values."""
        data = {"tags": ["a", "b", "c"]}

        result = flatten_dict(data)

        assert result["tags"] == "a; b; c"

    def test_flatten_list_of_dicts(self):
        """Test flattening list of dicts."""
        data = {"items": [{"id": 1}, {"id": 2}]}

        result = flatten_dict(data)

        assert result["items.count"] == 2

    def test_flatten_datetime(self):
        """Test flattening datetime value."""
        dt = datetime(2025, 1, 15, 10, 30, 0)
        data = {"timestamp": dt}

        result = flatten_dict(data)

        assert result["timestamp"] == "2025-01-15T10:30:00"

    def test_flatten_enum(self):
        """Test flattening enum value."""
        data = {"status": Status.ACTIVE}

        result = flatten_dict(data)

        assert result["status"] == "active"

    def test_flatten_none(self):
        """Test flattening None value."""
        data = {"value": None}

        result = flatten_dict(data)

        assert result["value"] == ""

    def test_flatten_custom_separator(self):
        """Test flattening with custom separator."""
        data = {"a": {"b": 1}}

        result = flatten_dict(data, separator="_")

        assert result == {"a_b": 1}


# =============================================================================
# CSVExporter Tests
# =============================================================================


class TestCSVExporter:
    """Tests for CSVExporter class."""

    def test_init_defaults(self):
        """Test default initialization."""
        exporter = CSVExporter()

        assert exporter.extension == ".csv"
        assert exporter.flatten is True
        assert exporter.delimiter == ","
        assert exporter.columns is None

    def test_init_custom_params(self, tmp_path: Path):
        """Test custom initialization."""
        exporter = CSVExporter(
            output_path=tmp_path / "out.csv",
            columns=["a", "b", "c"],
            flatten=False,
            delimiter=";",
        )

        assert exporter.columns == ["a", "b", "c"]
        assert exporter.flatten is False
        assert exporter.delimiter == ";"


class TestCSVExporterStreaming:
    """Tests for streaming mode."""

    def test_write_header_with_columns(self):
        """Test writing header with predefined columns."""
        stream = StringIO()

        with CSVExporter(stream=stream, columns=["url", "status"]) as exporter:
            exporter.write_header()

        stream.seek(0)
        content = stream.read()
        assert "url" in content
        assert "status" in content

    def test_write_header_from_meta(self):
        """Test writing header with columns from meta."""
        stream = StringIO()

        with CSVExporter(stream=stream) as exporter:
            exporter.write_header({"columns": ["a", "b", "c"]})

        stream.seek(0)
        reader = csv.reader(stream)
        header = next(reader)
        assert header == ["a", "b", "c"]

    def test_write_header_twice_raises(self):
        """Test writing header twice raises error."""
        stream = StringIO()

        with CSVExporter(stream=stream, columns=["a"]) as exporter:
            exporter.write_header()

            with pytest.raises(ExportWriteError, match="Header already written"):
                exporter.write_header()

    def test_write_single_item(self):
        """Test writing a single item."""
        stream = StringIO()
        item = {"url": "https://example.com", "status": 200}

        with CSVExporter(stream=stream) as exporter:
            exporter.write_item(item)

        stream.seek(0)
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["url"] == "https://example.com"
        assert rows[0]["status"] == "200"

    def test_write_multiple_items(self, sample_items):
        """Test writing multiple items."""
        stream = StringIO()

        with CSVExporter(stream=stream) as exporter:
            for item in sample_items:
                exporter.write_item(item)

        stream.seek(0)
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert len(rows) == 3

    def test_auto_detect_columns(self, sample_items):
        """Test columns are auto-detected from first item."""
        stream = StringIO()

        with CSVExporter(stream=stream) as exporter:
            exporter.write_item(sample_items[0])

            assert exporter.columns == ["url", "status", "title"]

    def test_write_nested_item_flattened(self, nested_item):
        """Test writing nested item with flattening."""
        stream = StringIO()

        with CSVExporter(stream=stream, flatten=True) as exporter:
            exporter.write_item(nested_item)

        stream.seek(0)
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert len(rows) == 1
        assert "meta.title" in rows[0]
        assert rows[0]["meta.title"] == "Example"

    def test_write_item_no_flatten(self):
        """Test writing item without flattening."""
        stream = StringIO()
        item = {"name": "test", "nested": {"key": "value"}}

        with CSVExporter(stream=stream, flatten=False) as exporter:
            exporter.write_item(item)

        stream.seek(0)
        content = stream.read()
        # Nested dict should be serialized as string
        assert "nested" in content

    def test_write_after_finalize_raises(self):
        """Test writing after finalize raises error."""
        stream = StringIO()

        exporter = CSVExporter(stream=stream, columns=["a"])
        exporter._finalized = True

        with pytest.raises(ExportWriteError, match="Cannot write after finalization"):
            exporter.write_item({"a": 1})

    def test_items_written_count(self, sample_items):
        """Test items_written counter."""
        stream = StringIO()

        with CSVExporter(stream=stream) as exporter:
            for item in sample_items:
                exporter.write_item(item)

            assert exporter._items_written == 3

    def test_extra_fields_ignored(self):
        """Test extra fields in later items are ignored."""
        stream = StringIO()

        with CSVExporter(stream=stream) as exporter:
            exporter.write_item({"a": 1, "b": 2})
            exporter.write_item({"a": 3, "b": 4, "c": 5})  # c is extra

        stream.seek(0)
        reader = csv.DictReader(stream)
        rows = list(reader)
        # c should not appear (extrasaction="ignore")
        assert "c" not in rows[0]


class TestCSVExporterBatch:
    """Tests for batch mode (export_report)."""

    def test_export_report_to_file(self, tmp_path: Path, mock_report):
        """Test exporting report to file."""
        output = tmp_path / "report.csv"

        exporter = CSVExporter(output_path=output)
        exporter.export_report(mock_report)

        assert output.exists()
        content = output.read_text()
        assert "https://example.com" in content
        assert "2.0.0" in content

    def test_export_report_contains_summary(self, tmp_path: Path, mock_report):
        """Test export contains summary fields."""
        output = tmp_path / "report.csv"

        exporter = CSVExporter(output_path=output)
        exporter.export_report(mock_report)

        content = output.read_text()
        assert "risk_score" in content
        assert "critical_findings" in content

    def test_export_report_ssl_info(self, tmp_path: Path, mock_report):
        """Test export includes SSL info."""
        output = tmp_path / "report.csv"

        exporter = CSVExporter(output_path=output)
        exporter.export_report(mock_report)

        reader = csv.DictReader(output.open())
        row = next(reader)
        assert row["ssl_grade"] == "A"

    def test_export_report_technologies(self, tmp_path: Path, mock_report):
        """Test export includes technologies."""
        output = tmp_path / "report.csv"

        exporter = CSVExporter(output_path=output)
        exporter.export_report(mock_report)

        reader = csv.DictReader(output.open())
        row = next(reader)
        assert "nginx" in row["technologies"]
        assert "Python" in row["technologies"]

    def test_export_report_no_output_raises(self, mock_report):
        """Test export_report without output raises error."""
        exporter = CSVExporter()

        with pytest.raises(ExportWriteError, match="No output stream or path"):
            exporter.export_report(mock_report)


class TestExportToCsv:
    """Tests for export_to_csv convenience function."""

    def test_export_list_to_csv(self, tmp_path: Path, sample_items):
        """Test exporting list of items."""
        output = tmp_path / "test.csv"

        count = export_to_csv(sample_items, output)

        assert count == 3
        assert output.exists()

        reader = csv.DictReader(output.open())
        rows = list(reader)
        assert len(rows) == 3

    def test_export_with_columns(self, tmp_path: Path, sample_items):
        """Test exporting with explicit columns."""
        output = tmp_path / "test.csv"

        export_to_csv(sample_items, output, columns=["url", "status"])

        reader = csv.DictReader(output.open())
        rows = list(reader)
        # title column should not be present
        assert "title" not in rows[0]

    def test_export_generator(self, tmp_path: Path):
        """Test exporting from generator."""
        output = tmp_path / "test.csv"

        def item_generator():
            for i in range(5):
                yield {"index": i, "value": i * 10}

        count = export_to_csv(item_generator(), output)

        assert count == 5


class TestCsvToDicts:
    """Tests for csv_to_dicts function."""

    def test_read_csv_file(self, tmp_path: Path):
        """Test reading CSV file."""
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("id,name\n1,first\n2,second\n3,third\n")

        rows = list(csv_to_dicts(csv_file))

        assert len(rows) == 3
        assert rows[0]["id"] == "1"
        assert rows[0]["name"] == "first"

    def test_read_csv_custom_delimiter(self, tmp_path: Path):
        """Test reading CSV with custom delimiter."""
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("id;name\n1;first\n2;second\n")

        rows = list(csv_to_dicts(csv_file, delimiter=";"))

        assert len(rows) == 2
        assert rows[0]["name"] == "first"


class TestCSVExporterFileOutput:
    """Tests for file output."""

    def test_output_to_file(self, tmp_path: Path, sample_items):
        """Test complete output to file."""
        output = tmp_path / "results.csv"

        with CSVExporter(output_path=output) as exporter:
            for item in sample_items:
                exporter.write_item(item)

        assert output.exists()
        reader = csv.DictReader(output.open())
        rows = list(reader)
        assert len(rows) == 3

    def test_finalize_is_idempotent(self, tmp_path: Path):
        """Test finalize can be called multiple times."""
        output = tmp_path / "test.csv"

        with CSVExporter(output_path=output, columns=["a"]) as exporter:
            exporter.write_item({"a": 1})
            exporter.finalize()
            exporter.finalize()  # Should not raise

        reader = csv.DictReader(output.open())
        rows = list(reader)
        assert len(rows) == 1
