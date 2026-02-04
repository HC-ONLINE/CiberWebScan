"""
Tests for JSON exporter.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ciberwebscan.export.base import ExportWriteError
from ciberwebscan.export.json import (
    JSONExporter,
    _json_serializer,
    dump,
    dumps,
    export_to_json,
)

# =============================================================================
# Test Fixtures
# =============================================================================


class Color(Enum):
    RED = "red"
    BLUE = "blue"


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
    report.meta = MagicMock()
    report.meta.target_url = "https://example.com"
    report.meta.timestamp = datetime(2025, 1, 15, 10, 0, 0)
    report.meta.duration_seconds = 5.5
    report.meta.version = "2.0.0"

    report.scrape = None
    report.fingerprint = None
    report.ssl = None
    report.headers = None
    report.cves = []
    report.attack = None
    report.risk_score = 25
    report.critical_findings = 0
    report.high_findings = 1
    report.medium_findings = 2
    report.low_findings = 0
    report.info_findings = 3

    # model_dump returns dict representation
    report.model_dump.return_value = {
        "meta": {
            "target_url": "https://example.com",
            "timestamp": "2025-01-15T10:00:00",
            "duration_seconds": 5.5,
            "version": "2.0.0",
        },
        "scrape": None,
        "fingerprint": None,
        "ssl": None,
        "headers": None,
        "cves": [],
        "attack": None,
        "risk_score": 25,
        "critical_findings": 0,
        "high_findings": 1,
        "medium_findings": 2,
        "low_findings": 0,
        "info_findings": 3,
    }

    return report


# =============================================================================
# JSON Serializer Tests
# =============================================================================


class TestJsonSerializer:
    """Tests for custom JSON serializer."""

    def test_serialize_datetime(self):
        """Test datetime serialization."""
        dt = datetime(2025, 1, 15, 10, 30, 0)

        result = _json_serializer(dt)

        assert result == "2025-01-15T10:30:00"

    def test_serialize_enum(self):
        """Test enum serialization."""
        result = _json_serializer(Color.RED)

        assert result == "red"

    def test_serialize_path(self):
        """Test Path serialization."""
        path = Path("home/user/file.txt")

        result = _json_serializer(path)

        # Path.str() uses OS-specific separators
        assert "home" in result
        assert "file.txt" in result

    def test_serialize_pydantic_model(self):
        """Test Pydantic model serialization."""
        model = MagicMock()
        model.model_dump.return_value = {"key": "value"}

        result = _json_serializer(model)

        assert result == {"key": "value"}

    def test_serialize_unsupported_raises(self):
        """Test unsupported type raises TypeError."""
        with pytest.raises(TypeError, match="not JSON serializable"):
            _json_serializer(object())


class TestDumps:
    """Tests for dumps function."""

    def test_dumps_dict(self):
        """Test dumping dictionary."""
        data = {"key": "value", "number": 42}

        result = dumps(data)

        parsed = json.loads(result)
        assert parsed == data

    def test_dumps_with_datetime(self):
        """Test dumping data with datetime."""
        data = {"timestamp": datetime(2025, 1, 15)}

        result = dumps(data)

        parsed = json.loads(result)
        assert parsed["timestamp"] == "2025-01-15T00:00:00"

    def test_dumps_with_indent(self):
        """Test dumping with indentation."""
        data = {"key": "value"}

        result = dumps(data, indent=2)

        assert "\n" in result
        assert "  " in result

    def test_dumps_compact(self):
        """Test compact dumping."""
        data = {"key": "value", "nested": {"a": 1}}

        result = dumps(data, indent=None)

        # Should have no newlines
        assert "\n" not in result


class TestDump:
    """Tests for dump function."""

    def test_dump_to_stream(self):
        """Test dumping to stream."""
        stream = StringIO()
        data = {"key": "value"}

        dump(data, stream)

        stream.seek(0)
        parsed = json.loads(stream.read())
        assert parsed == data


# =============================================================================
# JSONExporter Tests
# =============================================================================


class TestJSONExporter:
    """Tests for JSONExporter class."""

    def test_init_defaults(self):
        """Test default initialization."""
        exporter = JSONExporter()

        assert exporter.indent == 2
        assert exporter.items_key == "items"
        assert exporter.extension == ".json"

    def test_init_custom_params(self, tmp_path: Path):
        """Test custom initialization."""
        exporter = JSONExporter(
            output_path=tmp_path / "out.json",
            indent=4,
            items_key="results",
            include_raw=True,
        )

        assert exporter.indent == 4
        assert exporter.items_key == "results"
        assert exporter.include_raw


class TestJSONExporterStreaming:
    """Tests for streaming mode."""

    def test_write_header_simple(self):
        """Test writing header without meta."""
        stream = StringIO()

        with JSONExporter(stream=stream) as exporter:
            exporter.write_header()

        content = stream.getvalue()
        assert content.startswith("{")
        assert '"items":' in content

    def test_write_header_with_meta(self):
        """Test writing header with metadata."""
        stream = StringIO()
        meta = {"version": "2.0", "timestamp": "2025-01-15"}

        with JSONExporter(stream=stream) as exporter:
            exporter.write_header(meta)

        content = stream.getvalue()
        assert '"meta":' in content
        assert '"version"' in content

    def test_write_header_twice_raises(self):
        """Test writing header twice raises error."""
        stream = StringIO()

        with JSONExporter(stream=stream) as exporter:
            exporter.write_header()

            with pytest.raises(ExportWriteError, match="Header already written"):
                exporter.write_header()

    def test_write_single_item(self):
        """Test writing a single item."""
        stream = StringIO()
        item = {"url": "https://example.com", "status": 200}

        with JSONExporter(stream=stream) as exporter:
            exporter.write_header()
            exporter.write_item(item)

        content = stream.getvalue()
        parsed = json.loads(content)
        assert len(parsed["items"]) == 1
        assert parsed["items"][0]["url"] == "https://example.com"

    def test_write_multiple_items(self, sample_items):
        """Test writing multiple items."""
        stream = StringIO()

        with JSONExporter(stream=stream) as exporter:
            exporter.write_header()
            for item in sample_items:
                exporter.write_item(item)

        content = stream.getvalue()
        parsed = json.loads(content)
        assert len(parsed["items"]) == 3

    def test_write_item_auto_starts(self):
        """Test write_item auto-starts without header."""
        stream = StringIO()

        with JSONExporter(stream=stream) as exporter:
            exporter.write_item({"test": "data"})

        content = stream.getvalue()
        parsed = json.loads(content)
        assert "items" in parsed

    def test_write_after_finalize_raises(self):
        """Test writing after finalize raises error."""
        stream = StringIO()

        exporter = JSONExporter(stream=stream)
        exporter._started = True
        exporter._finalized = True

        with pytest.raises(ExportWriteError, match="Cannot write after finalization"):
            exporter.write_item({"test": "data"})

    def test_compact_mode(self):
        """Test compact JSON (no indentation)."""
        stream = StringIO()

        with JSONExporter(stream=stream, indent=None) as exporter:
            exporter.write_header()
            exporter.write_item({"test": "data"})

        content = stream.getvalue()
        # Compact should be on one line (minus closing)
        assert content.count("\n") <= 1

    def test_items_written_count(self, sample_items):
        """Test items_written counter."""
        stream = StringIO()

        with JSONExporter(stream=stream) as exporter:
            for item in sample_items:
                exporter.write_item(item)

            assert exporter._items_written == 3


class TestJSONExporterBatch:
    """Tests for batch mode (export_report)."""

    def test_export_report_to_file(self, tmp_path: Path, mock_report):
        """Test exporting report to file."""
        output = tmp_path / "report.json"

        exporter = JSONExporter(output_path=output)
        exporter.export_report(mock_report)

        assert output.exists()
        content = json.loads(output.read_text())
        assert content["meta"]["target_url"] == "https://example.com"

    def test_export_report_to_stream(self, mock_report):
        """Test exporting report to stream."""
        stream = StringIO()

        exporter = JSONExporter(stream=stream)
        exporter.export_report(mock_report)

        stream.seek(0)
        content = json.loads(stream.read())
        assert content["meta"]["version"] == "2.0.0"

    def test_export_report_after_streaming_raises(self, mock_report):
        """Test export_report after streaming writes raises error."""
        stream = StringIO()

        with (
            pytest.raises(ExportWriteError, match="Cannot use export_report"),
            JSONExporter(stream=stream) as exporter,
        ):
            exporter.write_item({"test": "data"})
            exporter.export_report(mock_report)

    def test_export_report_no_output_raises(self, mock_report):
        """Test export_report without output raises error."""
        exporter = JSONExporter()

        with pytest.raises(ExportWriteError, match="No output stream or path"):
            exporter.export_report(mock_report)


class TestExportToJson:
    """Tests for export_to_json convenience function."""

    def test_export_dict_to_json(self, tmp_path: Path):
        """Test exporting dictionary."""
        output = tmp_path / "test.json"
        data = {"key": "value", "items": [1, 2, 3]}

        export_to_json(data, output)

        content = json.loads(output.read_text())
        assert content == data

    def test_export_pydantic_model(self, tmp_path: Path):
        """Test exporting Pydantic model."""
        output = tmp_path / "test.json"

        model = MagicMock()
        model.model_dump.return_value = {"name": "test"}

        export_to_json(model, output)

        content = json.loads(output.read_text())
        assert content == {"name": "test"}

    def test_export_with_indent(self, tmp_path: Path):
        """Test export with custom indent."""
        output = tmp_path / "test.json"
        data = {"key": "value"}

        export_to_json(data, output, indent=2)

        content = output.read_text()
        # orjson uses fixed 2-space indent regardless of indent param
        assert "\n" in content  # Has newlines (pretty printed)


class TestJSONExporterFileOutput:
    """Tests for file output."""

    def test_output_to_file(self, tmp_path: Path, sample_items):
        """Test complete output to file."""
        output = tmp_path / "results.json"

        with JSONExporter(output_path=output) as exporter:
            exporter.write_header({"version": "2.0"})
            for item in sample_items:
                exporter.write_item(item)

        assert output.exists()
        content = json.loads(output.read_text())
        assert content["meta"]["version"] == "2.0"
        assert len(content["items"]) == 3

    def test_finalize_only_called_once(self, tmp_path: Path):
        """Test finalize is idempotent."""
        output = tmp_path / "test.json"

        with JSONExporter(output_path=output) as exporter:
            exporter.write_item({"test": 1})
            exporter.finalize()
            # Second finalize should be no-op
            exporter.finalize()

        content = json.loads(output.read_text())
        assert "items" in content
