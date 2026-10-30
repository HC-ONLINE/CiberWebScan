"""Tests for CLI output formatting."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

from ciberwebscan.cli.output import (
    format_duration,
    format_scrape_result,
    format_size,
    format_timestamp,
    print_dict,
    print_error,
    print_header,
    print_info,
    print_key_value,
    print_list,
    print_success,
    print_warning,
)
from ciberwebscan.export.models import FormInfo

pytestmark = pytest.mark.unit


class TestPrintFunctions:
    """Tests for basic print functions."""

    def test_print_error(self, capsys):
        """Test error output goes to stderr."""
        print_error("test error")
        captured = capsys.readouterr()
        assert "ERROR: test error" in captured.err

    def test_print_warning(self, capsys):
        """Test warning output goes to stderr."""
        print_warning("test warning")
        captured = capsys.readouterr()
        assert "WARNING: test warning" in captured.err

    def test_print_success(self, capsys):
        """Test success output."""
        print_success("operation completed")
        captured = capsys.readouterr()
        assert "OK: operation completed" in captured.out

    def test_print_info(self, capsys):
        """Test info output."""
        print_info("some information")
        captured = capsys.readouterr()
        assert "some information" in captured.out

    def test_print_header(self, capsys):
        """Test header formatting."""
        print_header("Section Title")
        captured = capsys.readouterr()
        assert "=== Section Title ===" in captured.out

    def test_print_key_value(self, capsys):
        """Test key-value formatting."""
        print_key_value("name", "value")
        captured = capsys.readouterr()
        assert "name: value" in captured.out

    def test_print_key_value_with_indent(self, capsys):
        """Test indented key-value."""
        print_key_value("key", "val", indent=2)
        captured = capsys.readouterr()
        assert "    key: val" in captured.out

    def test_print_list(self, capsys):
        """Test list formatting."""
        print_list(["item1", "item2", "item3"])
        captured = capsys.readouterr()
        assert "- item1" in captured.out
        assert "- item2" in captured.out
        assert "- item3" in captured.out

    def test_print_dict(self, capsys):
        """Test dictionary formatting."""
        print_dict({"key1": "value1", "key2": "value2"})
        captured = capsys.readouterr()
        assert "key1: value1" in captured.out
        assert "key2: value2" in captured.out

    def test_print_dict_nested(self, capsys):
        """Test nested dictionary formatting."""
        print_dict({"outer": {"inner": "value"}})
        captured = capsys.readouterr()
        assert "outer:" in captured.out
        assert "inner: value" in captured.out


class TestFormatFunctions:
    """Tests for format helper functions."""

    def test_format_duration_milliseconds(self):
        """Test duration formatting for ms."""
        assert format_duration(0.5) == "500ms"
        assert format_duration(0.001) == "1ms"

    def test_format_duration_seconds(self):
        """Test duration formatting for seconds."""
        assert format_duration(1.5) == "1.50s"
        assert format_duration(30) == "30.00s"

    def test_format_duration_minutes(self):
        """Test duration formatting for minutes."""
        assert format_duration(90) == "1m 30s"
        assert format_duration(120) == "2m 0s"

    def test_format_timestamp_valid(self):
        """Test timestamp formatting."""
        dt = datetime(2025, 1, 15, 10, 30, 45)
        result = format_timestamp(dt)
        assert "2025-01-15" in result
        assert "10:30:45" in result

    def test_format_timestamp_none(self):
        """Test timestamp formatting with None."""
        assert format_timestamp(None) == "N/A"

    def test_format_size_bytes(self):
        """Test size formatting in bytes."""
        assert format_size(500) == "500.0 B"

    def test_format_size_kilobytes(self):
        """Test size formatting in KB."""
        assert format_size(2048) == "2.0 KB"

    def test_format_size_megabytes(self):
        """Test size formatting in MB."""
        assert format_size(1048576) == "1.0 MB"


class TestFormatScrapeResultForms:
    """Tests for displaying extracted forms in scrape output."""

    def _result(self, forms):
        """Build a minimal object exposing the scrape-result attributes used."""
        return SimpleNamespace(
            url="https://example.com",
            status_code=200,
            title="Page",
            elapsed_ms=12.0,
            text_content="body",
            forms=forms,
        )

    def test_forms_section_displayed(self, capsys):
        """Forms are shown with action and method."""
        forms = [{"action": "/login", "method": "POST", "fields": []}]
        format_scrape_result(self._result(forms))
        out = capsys.readouterr().out
        assert "Forms (1)" in out
        assert "POST /login" in out

    def test_field_markers_displayed(self, capsys):
        """Required, readonly, hidden and CSRF markers are shown."""
        forms = [
            {
                "action": "/x",
                "method": "POST",
                "name": "f",
                "fields": [
                    {"name": "user", "type": "text", "required": True},
                    {"name": "code", "type": "text", "readonly": True},
                    {
                        "name": "csrfmiddlewaretoken",
                        "type": "hidden",
                        "is_hidden": True,
                        "is_csrf_token": True,
                    },
                ],
            }
        ]
        format_scrape_result(self._result(forms))
        out = capsys.readouterr().out
        assert "user (text) [*]" in out
        assert "code (text) [RO]" in out
        assert "csrfmiddlewaretoken (hidden) [HIDDEN CSRF]" in out

    def test_label_and_options_displayed(self, capsys):
        """Labels and select options are rendered when present."""
        forms = [
            {
                "action": "/x",
                "method": "GET",
                "fields": [
                    {
                        "name": "plan",
                        "type": "select",
                        "label": "Plan",
                        "options": ["free", "pro"],
                    }
                ],
            }
        ]
        format_scrape_result(self._result(forms))
        out = capsys.readouterr().out
        assert '"Plan"' in out
        assert "options=['free', 'pro']" in out

    def test_token_value_not_printed(self, capsys):
        """Sensitive token values are not echoed by default."""
        forms = [
            {
                "action": "/x",
                "method": "POST",
                "fields": [
                    {
                        "name": "csrf_token",
                        "type": "hidden",
                        "value": "SUPERSECRET",
                        "is_hidden": True,
                        "is_csrf_token": True,
                    }
                ],
            }
        ]
        format_scrape_result(self._result(forms))
        assert "SUPERSECRET" not in capsys.readouterr().out

    def test_empty_forms_list_no_section(self, capsys):
        """An empty forms list renders no Forms section."""
        format_scrape_result(self._result([]))
        out = capsys.readouterr().out
        assert "Forms" not in out

    def test_missing_forms_attribute_no_crash(self, capsys):
        """An object without a forms attribute renders without crashing."""
        result = SimpleNamespace(
            url="https://example.com",
            status_code=200,
            title="Page",
            elapsed_ms=1.0,
            text_content="body",
        )
        format_scrape_result(result)
        out = capsys.readouterr().out
        assert "Scrape Result" in out
        assert "Forms" not in out

    def test_forminfo_objects_displayed(self, capsys):
        """FormInfo model instances (attribute access) render correctly."""
        form = FormInfo(
            action="/login",
            method="POST",
            name="login",
            fields=[{"name": "user", "type": "text", "required": True}],
        )
        format_scrape_result(self._result([form]))
        out = capsys.readouterr().out
        assert "POST /login" in out
        assert '(name="login")' in out
        assert "user (text) [*]" in out
