"""
Tests for HTML exporter.
"""

from __future__ import annotations

from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ciberwebscan.export.base import ExportWriteError
from ciberwebscan.export.html import (
    HTMLExporter,
    _bool_icon,
    _escape,
    _grade_class,
    _render_table,
    _severity_badge,
    export_to_html,
    severity_upper,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_items():
    """Sample items for testing."""
    return [
        {"url": "https://example.com/1", "status": 200, "type": "page"},
        {"url": "https://example.com/2", "status": 404, "type": "error"},
        {"url": "https://example.com/3", "status": 500, "type": "server_error"},
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


@pytest.fixture
def mock_report_with_ssl():
    """Create a mock AnalysisReport with SSL data."""
    report = MagicMock()
    report.meta = MagicMock()
    report.meta.target_url = "https://secure.example.com"
    report.meta.timestamp = datetime(2025, 1, 15, 10, 0, 0)
    report.meta.duration_seconds = 3.2
    report.meta.version = "2.0.0"

    report.scrape = None
    report.fingerprint = None
    report.cves = []
    report.attack = None
    report.risk_score = 15
    report.critical_findings = 0
    report.high_findings = 0
    report.medium_findings = 1
    report.low_findings = 1
    report.info_findings = 3

    # SSL data
    report.ssl = MagicMock()
    report.ssl.is_https = True
    report.ssl.protocol_version = "TLSv1.3"
    report.ssl.cipher_suite = "TLS_AES_256_GCM_SHA384"
    report.ssl.grade = "A"
    report.ssl.chain_valid = True
    report.ssl.ocsp_stapling = True
    report.ssl.certificate = MagicMock()
    report.ssl.certificate.subject = {"CN": "example.com"}
    report.ssl.certificate.issuer = {"CN": "Let's Encrypt"}
    report.ssl.certificate.not_before = datetime(2025, 1, 1)
    report.ssl.certificate.not_after = datetime(2025, 4, 1)
    report.ssl.certificate.days_until_expiry = 75
    report.ssl.certificate.is_expired = False
    report.ssl.certificate.is_self_signed = False
    report.ssl.certificate.signature_algorithm = "SHA256withRSA"
    report.ssl.certificate.public_key_algorithm = "RSA"
    report.ssl.certificate.public_key_bits = 2048
    report.ssl.findings = []

    report.model_dump.return_value = {
        "meta": {
            "target_url": "https://secure.example.com",
            "timestamp": "2025-01-15T10:00:00",
            "duration_seconds": 3.2,
            "version": "2.0.0",
        },
        "ssl": {
            "is_https": True,
            "protocol_version": "TLSv1.3",
            "grade": "A",
        },
        "risk_score": 15,
        "critical_findings": 0,
        "high_findings": 0,
        "medium_findings": 1,
        "low_findings": 1,
        "info_findings": 3,
    }

    return report


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestEscape:
    """Tests for HTML escape helper."""

    def test_escape_none(self):
        """Test escaping None returns empty string."""
        assert _escape(None) == ""

    def test_escape_string(self):
        """Test escaping regular string."""
        assert _escape("hello") == "hello"

    def test_escape_html_chars(self):
        """Test escaping HTML special characters."""
        result = _escape('<script>alert("xss")</script>')
        assert "<script>" not in result
        assert "&lt;" in result
        assert "&gt;" in result

    def test_escape_ampersand(self):
        """Test escaping ampersand."""
        assert _escape("a & b") == "a &amp; b"

    def test_escape_quotes(self):
        """Test escaping quotes."""
        result = _escape('key="value"')
        assert "key=" in result
        assert "&quot;" in result


class TestSeverityBadge:
    """Tests for severity badge HTML generation."""

    def test_badge_critical(self):
        """Test critical severity badge."""
        result = _severity_badge("critical")
        assert "badge-critical" in result
        assert "CRITICAL" in result

    def test_badge_high(self):
        """Test high severity badge."""
        result = _severity_badge("high")
        assert "badge-high" in result
        assert "HIGH" in result

    def test_badge_medium(self):
        """Test medium severity badge."""
        result = _severity_badge("medium")
        assert "badge-medium" in result

    def test_badge_low(self):
        """Test low severity badge."""
        result = _severity_badge("low")
        assert "badge-low" in result

    def test_badge_info(self):
        """Test info severity badge."""
        result = _severity_badge("info")
        assert "badge-info" in result


class TestSeverityUpper:
    """Tests for severity_upper helper."""

    def test_upper_lowercase(self):
        """Test uppercase conversion."""
        assert severity_upper("critical") == "CRITICAL"

    def test_upper_already_upper(self):
        """Test already uppercase."""
        assert severity_upper("HIGH") == "HIGH"

    def test_upper_empty(self):
        """Test empty string."""
        assert severity_upper("") == ""


class TestGradeClass:
    """Tests for grade CSS class helper."""

    def test_grade_a(self):
        """Test grade A."""
        assert _grade_class("A") == "grade-a"

    def test_grade_a_plus(self):
        """Test grade A+."""
        assert _grade_class("A+") == "grade-a-plus"

    def test_grade_b(self):
        """Test grade B."""
        assert _grade_class("B") == "grade-b"

    def test_grade_f(self):
        """Test grade F."""
        assert _grade_class("F") == "grade-f"

    def test_grade_none(self):
        """Test None grade."""
        assert _grade_class(None) == "grade-f"

    def test_grade_lowercase(self):
        """Test lowercase grade."""
        assert _grade_class("a") == "grade-a"


class TestBoolIcon:
    """Tests for boolean icon helper."""

    def test_bool_true(self):
        """Test True value."""
        result = _bool_icon(True)
        assert "YES" in result
        assert "badge-present" in result

    def test_bool_false(self):
        """Test False value."""
        result = _bool_icon(False)
        assert "NO" in result
        assert "badge-missing" in result


class TestRenderTable:
    """Tests for HTML table rendering."""

    def test_render_empty_table(self):
        """Test rendering empty table."""
        result = _render_table([], ["col1", "col2"])
        assert "No data available" in result

    def test_render_single_row(self):
        """Test rendering single row."""
        rows = [{"name": "test", "value": 42}]
        result = _render_table(rows, ["name", "value"])
        assert "<table>" in result
        assert "test" in result
        assert "42" in result

    def test_render_multiple_rows(self):
        """Test rendering multiple rows."""
        rows = [
            {"name": "a", "value": 1},
            {"name": "b", "value": 2},
        ]
        result = _render_table(rows, ["name", "value"])
        assert result.count("<tr>") == 3  # header + 2 rows

    def test_render_bool_column(self):
        """Test rendering boolean column with badges."""
        rows = [{"active": True}]
        result = _render_table(rows, ["active"])
        assert "badge-present" in result

    def test_render_list_column(self):
        """Test rendering list column."""
        rows = [{"tags": ["a", "b", "c"]}]
        result = _render_table(rows, ["tags"])
        assert "a, b, c" in result


# =============================================================================
# HTMLExporter Tests
# =============================================================================


class TestHTMLExporterInit:
    """Tests for HTMLExporter initialization."""

    def test_init_defaults(self):
        """Test default initialization."""
        exporter = HTMLExporter()

        assert exporter.extension == ".html"
        assert exporter._items == []
        assert exporter._meta is None

    def test_init_with_output_path(self, tmp_path: Path):
        """Test initialization with output path."""
        exporter = HTMLExporter(output_path=tmp_path / "report.html")

        assert exporter.output_path == tmp_path / "report.html"

    def test_init_with_stream(self):
        """Test initialization with stream."""
        stream = StringIO()
        exporter = HTMLExporter(stream=stream)

        assert exporter._stream is stream


class TestHTMLExporterStreaming:
    """Tests for streaming mode."""

    def test_write_header(self):
        """Test writing header."""
        stream = StringIO()

        with HTMLExporter(stream=stream) as exporter:
            exporter.write_header({"target_url": "https://example.com"})

        assert exporter._meta == {"target_url": "https://example.com"}

    def test_write_header_twice_raises(self):
        """Test writing header twice raises error."""
        stream = StringIO()

        with HTMLExporter(stream=stream) as exporter:
            exporter.write_header()

            with pytest.raises(ExportWriteError, match="Header already written"):
                exporter.write_header()

    def test_write_single_item(self):
        """Test writing a single item."""
        stream = StringIO()
        item = {"url": "https://example.com", "status": 200}

        with HTMLExporter(stream=stream) as exporter:
            exporter.write_header()
            exporter.write_item(item)

        content = stream.getvalue()
        assert "<!DOCTYPE html>" in content
        assert "CiberWebScan" in content
        assert "example.com" in content

    def test_write_multiple_items(self, sample_items):
        """Test writing multiple items."""
        stream = StringIO()

        with HTMLExporter(stream=stream) as exporter:
            exporter.write_header()
            for item in sample_items:
                exporter.write_item(item)

        content = stream.getvalue()
        assert "Items: 3" in content

    def test_write_item_auto_starts(self):
        """Test write_item auto-starts without header."""
        stream = StringIO()

        with HTMLExporter(stream=stream) as exporter:
            exporter.write_item({"test": "data"})

        content = stream.getvalue()
        assert "<!DOCTYPE html>" in content

    def test_write_after_finalize_raises(self):
        """Test writing after finalize raises error."""
        stream = StringIO()

        exporter = HTMLExporter(stream=stream)
        exporter._started = True
        exporter._finalized = True

        with pytest.raises(ExportWriteError, match="Cannot write after finalization"):
            exporter.write_item({"test": "data"})

    def test_items_written_count(self, sample_items):
        """Test items_written counter."""
        stream = StringIO()

        with HTMLExporter(stream=stream) as exporter:
            for item in sample_items:
                exporter.write_item(item)

            assert exporter._items_written == 3

    def test_finalize_produces_valid_html(self):
        """Test finalize produces valid HTML structure."""
        stream = StringIO()

        with HTMLExporter(stream=stream) as exporter:
            exporter.write_item({"test": "data"})

        content = stream.getvalue()
        assert content.startswith("<!DOCTYPE html>")
        assert "<html" in content
        assert "</html>" in content
        assert "<head>" in content
        assert "<body>" in content
        assert "<style>" in content

    def test_finalize_includes_css(self):
        """Test finalize includes embedded CSS."""
        stream = StringIO()

        with HTMLExporter(stream=stream) as exporter:
            exporter.write_item({"test": "data"})

        content = stream.getvalue()
        assert "--bg-primary" in content
        assert "--text-primary" in content


class TestHTMLExporterBatch:
    """Tests for batch mode (export_report)."""

    def test_export_report_to_file(self, tmp_path: Path, mock_report):
        """Test exporting report to file."""
        output = tmp_path / "report.html"

        exporter = HTMLExporter(output_path=output)
        exporter.export_report(mock_report)

        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "CiberWebScan Security Report" in content
        assert "https://example.com" in content

    def test_export_report_to_stream(self, mock_report):
        """Test exporting report to stream."""
        stream = StringIO()

        exporter = HTMLExporter(stream=stream)
        exporter.export_report(mock_report)

        stream.seek(0)
        content = stream.read()
        assert "CiberWebScan Security Report" in content
        assert "Risk Score" in content

    def test_export_report_after_streaming_raises(self, mock_report):
        """Test export_report after streaming writes raises error."""
        stream = StringIO()

        with (
            pytest.raises(ExportWriteError, match="Cannot use export_report"),
            HTMLExporter(stream=stream) as exporter,
        ):
            exporter.write_item({"test": "data"})
            exporter.export_report(mock_report)

    def test_export_report_no_output_raises(self, mock_report):
        """Test export_report without output raises error."""
        exporter = HTMLExporter()

        with pytest.raises(ExportWriteError, match="No output stream or path"):
            exporter.export_report(mock_report)

    def test_export_report_with_ssl(self, tmp_path: Path, mock_report_with_ssl):
        """Test exporting report with SSL data."""
        output = tmp_path / "report.html"

        exporter = HTMLExporter(output_path=output)
        exporter.export_report(mock_report_with_ssl)

        content = output.read_text(encoding="utf-8")
        assert "SSL/TLS Analysis" in content
        assert "TLSv1.3" in content
        assert "grade-a" in content

    def test_export_report_calculates_summary(self, mock_report):
        """Test export_report calls calculate_summary."""
        stream = StringIO()

        exporter = HTMLExporter(stream=stream)
        exporter.export_report(mock_report)

        mock_report.calculate_summary.assert_called_once()


class TestExportToHTML:
    """Tests for export_to_html convenience function."""

    def test_export_report_to_html(self, tmp_path: Path, mock_report):
        """Test exporting AnalysisReport to HTML."""
        output = tmp_path / "report.html"

        export_to_html(mock_report, output)

        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "CiberWebScan" in content

    def test_export_dict_to_html(self, tmp_path: Path):
        """Test exporting dictionary to HTML."""
        output = tmp_path / "data.html"
        data = {"key": "value", "number": 42}

        export_to_html(data, output)

        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "key" in content
        assert "value" in content


class TestHTMLExporterFileOutput:
    """Tests for file output."""

    def test_output_to_file(self, tmp_path: Path, sample_items):
        """Test complete output to file."""
        output = tmp_path / "results.html"

        with HTMLExporter(output_path=output) as exporter:
            exporter.write_header({"target_url": "https://example.com"})
            for item in sample_items:
                exporter.write_item(item)

        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "Items: 3" in content
        assert "example.com" in content

    def test_finalize_only_called_once(self, tmp_path: Path):
        """Test finalize is idempotent."""
        output = tmp_path / "test.html"

        with HTMLExporter(output_path=output) as exporter:
            exporter.write_item({"test": 1})
            exporter.finalize()
            # Second finalize should be no-op
            exporter.finalize()

        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_html_is_self_contained(self, tmp_path: Path):
        """Test HTML output is self-contained (no external resources)."""
        output = tmp_path / "self_contained.html"

        with HTMLExporter(output_path=output) as exporter:
            exporter.write_item({"test": "data"})

        content = output.read_text(encoding="utf-8")
        # Should not reference external CSS/JS
        assert 'src="' not in content
        assert 'href="*.css"' not in content
        # CSS should be inline
        assert "<style>" in content
