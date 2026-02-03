"""
Tests for base exporter classes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ciberwebscan.export.base import (
    ExportError,
    ExportValidationError,
    StreamingExporter,
    export_to_file,
    get_exporter,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class SampleDataclass:
    """Sample dataclass for testing serialization."""

    name: str
    value: int


class ConcreteExporter(StreamingExporter):
    """Concrete implementation for testing abstract base class."""

    extension = ".test"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.written_items = []
        self.header_meta = None

    def write_header(self, meta=None):
        self._started = True
        self.header_meta = meta
        self.stream.write("HEADER\n")

    def write_item(self, item):
        if not self._started:
            self.write_header()
        data = self._serialize_item(item)
        self.written_items.append(data)
        self.stream.write(f"ITEM: {data}\n")
        self._items_written += 1

    def finalize(self):
        self.stream.write("FOOTER\n")
        self._finalized = True

    def export_report(self, report):
        self.stream.write(f"REPORT: {report}\n")
        self._finalized = True


# =============================================================================
# BaseExporter Tests
# =============================================================================


class TestBaseExporter:
    """Tests for BaseExporter abstract class."""

    def test_init_with_path(self, tmp_path: Path):
        """Test initialization with output path."""
        output_file = tmp_path / "output.test"
        exporter = ConcreteExporter(output_path=output_file)

        assert exporter.output_path == output_file
        assert exporter._stream is None
        assert exporter._items_written == 0
        assert not exporter._started
        assert not exporter._finalized

    def test_init_with_stream(self):
        """Test initialization with stream."""
        stream = StringIO()
        exporter = ConcreteExporter(stream=stream)

        assert exporter.output_path is None
        assert exporter._stream is stream
        assert not exporter._owns_stream

    def test_context_manager_opens_file(self, tmp_path: Path):
        """Test context manager opens file automatically."""
        output_file = tmp_path / "output.test"

        with ConcreteExporter(output_path=output_file) as exporter:
            assert exporter._stream is not None
            assert exporter._owns_stream
            exporter.write_item({"test": "data"})

        # File should be closed after context manager
        assert exporter._stream is None
        assert output_file.exists()

    def test_context_manager_finalizes(self, tmp_path: Path):
        """Test context manager calls finalize on exit."""
        output_file = tmp_path / "output.test"

        with ConcreteExporter(output_path=output_file) as exporter:
            exporter.write_item({"test": "data"})

        assert exporter._finalized
        content = output_file.read_text()
        assert "FOOTER" in content

    def test_no_stream_or_path_raises_error(self):
        """Test error when no stream or path provided."""
        exporter = ConcreteExporter()

        with pytest.raises(ExportError, match="No output path or stream"), exporter:
            pass

    def test_stream_property_without_context_raises(self):
        """Test accessing stream without context manager raises error."""
        exporter = ConcreteExporter(output_path=Path("test.txt"))

        with pytest.raises(ExportError, match="No output stream"):
            _ = exporter.stream


class TestSerialization:
    """Tests for item serialization methods."""

    def test_serialize_dict(self):
        """Test serializing plain dict."""
        exporter = ConcreteExporter(stream=StringIO())
        data = {"key": "value", "number": 42}

        result = exporter._serialize_item(data)

        assert result == data

    def test_serialize_pydantic_v2(self):
        """Test serializing Pydantic v2 model."""
        exporter = ConcreteExporter(stream=StringIO())

        mock_model = MagicMock()
        mock_model.model_dump.return_value = {"name": "test", "value": 123}

        result = exporter._serialize_item(mock_model)

        assert result == {"name": "test", "value": 123}
        mock_model.model_dump.assert_called_once()

    def test_serialize_pydantic_v1(self):
        """Test serializing Pydantic v1 model (fallback)."""
        exporter = ConcreteExporter(stream=StringIO())

        mock_model = MagicMock(spec=["dict"])
        mock_model.dict.return_value = {"name": "test"}
        # Ensure model_dump is not present
        del mock_model.model_dump

        result = exporter._serialize_item(mock_model)

        assert result == {"name": "test"}

    def test_serialize_dataclass(self):
        """Test serializing dataclass."""
        exporter = ConcreteExporter(stream=StringIO())
        data = SampleDataclass(name="test", value=42)

        result = exporter._serialize_item(data)

        assert result == {"name": "test", "value": 42}

    def test_serialize_unsupported_type_raises(self):
        """Test serializing unsupported type raises error."""
        exporter = ConcreteExporter(stream=StringIO())

        with pytest.raises(ExportValidationError, match="Cannot serialize"):
            exporter._serialize_item("plain string")

    def test_format_datetime(self):
        """Test datetime formatting."""
        exporter = ConcreteExporter(stream=StringIO())
        dt = datetime(2025, 1, 15, 10, 30, 0)

        result = exporter._format_datetime(dt)

        assert result == "2025-01-15T10:30:00"

    def test_format_datetime_none(self):
        """Test formatting None datetime."""
        exporter = ConcreteExporter(stream=StringIO())

        result = exporter._format_datetime(None)

        assert result is None


class TestStreamingExporter:
    """Tests for StreamingExporter class."""

    def test_flush(self):
        """Test flush method."""
        stream = StringIO()
        exporter = ConcreteExporter(stream=stream)

        exporter.write_item({"test": "data"})
        exporter.flush()

        # StringIO flush is a no-op but should not raise
        assert exporter._items_written == 1

    def test_buffer_size_parameter(self):
        """Test buffer_size parameter is stored."""
        exporter = ConcreteExporter(stream=StringIO(), buffer_size=4096)

        assert exporter.buffer_size == 4096


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestGetExporter:
    """Tests for get_exporter factory function."""

    def test_get_json_exporter(self, tmp_path: Path):
        """Test getting JSON exporter."""
        exporter = get_exporter("json", tmp_path / "out.json")

        assert exporter.__class__.__name__ == "JSONExporter"

    def test_get_jsonl_exporter(self, tmp_path: Path):
        """Test getting JSONL exporter."""
        exporter = get_exporter("jsonl", tmp_path / "out.jsonl")

        assert exporter.__class__.__name__ == "JSONLExporter"

    def test_get_csv_exporter(self, tmp_path: Path):
        """Test getting CSV exporter."""
        exporter = get_exporter("csv", tmp_path / "out.csv")

        assert exporter.__class__.__name__ == "CSVExporter"

    def test_unknown_format_raises(self):
        """Test unknown format raises error."""
        with pytest.raises(ExportError, match="Unknown export format"):
            get_exporter("xml", Path("out.xml"))

    def test_case_insensitive(self, tmp_path: Path):
        """Test format is case insensitive."""
        exporter = get_exporter("JSON", tmp_path / "out.json")

        assert exporter.__class__.__name__ == "JSONExporter"


class TestExportToFile:
    """Tests for export_to_file context manager."""

    def test_export_to_file_json(self, tmp_path: Path):
        """Test export_to_file with JSON format."""
        output = tmp_path / "test.json"

        with export_to_file(output, format="json") as exporter:
            exporter.write_item({"name": "test"})

        assert output.exists()
        content = output.read_text()
        assert "test" in content

    def test_export_to_file_jsonl(self, tmp_path: Path):
        """Test export_to_file with JSONL format."""
        output = tmp_path / "test.jsonl"

        with export_to_file(output, format="jsonl") as exporter:
            exporter.write_item({"name": "item1"})
            exporter.write_item({"name": "item2"})

        assert output.exists()
        lines = output.read_text().strip().split("\n")
        assert len(lines) >= 2

    def test_export_to_file_csv(self, tmp_path: Path):
        """Test export_to_file with CSV format."""
        output = tmp_path / "test.csv"

        with export_to_file(output, format="csv") as exporter:
            exporter.write_item({"name": "test", "value": 42})

        assert output.exists()
        content = output.read_text()
        assert "name" in content
        assert "value" in content

    def test_export_to_file_invalid_format(self, tmp_path: Path):
        """Test export_to_file with invalid format."""
        with (
            pytest.raises(ExportError, match="Unknown export format"),
            export_to_file(tmp_path / "test.xml", format="xml"),
        ):
            pass
