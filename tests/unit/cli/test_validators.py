"""Tests for CLI validators."""

from __future__ import annotations

from pathlib import Path

import pytest

from ciberwebscan.cli.validators import (
    ValidationError,
    validate_file_path,
    validate_format,
    validate_selector,
    validate_timeout,
    validate_url,
)


class TestValidateUrl:
    """Tests for URL validation."""

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        result = validate_url("https://example.com")
        assert result == "https://example.com"

    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        result = validate_url("http://example.com")
        assert result == "http://example.com"

    def test_url_without_scheme(self):
        """Test URL without scheme adds https."""
        result = validate_url("example.com")
        assert result == "https://example.com"

    def test_url_with_path(self):
        """Test URL with path."""
        result = validate_url("https://example.com/path/to/page")
        assert result == "https://example.com/path/to/page"

    def test_url_with_port(self):
        """Test URL with port."""
        result = validate_url("https://example.com:8080")
        assert result == "https://example.com:8080"

    def test_localhost(self):
        """Test localhost URL."""
        result = validate_url("http://localhost:3000")
        assert result == "http://localhost:3000"

    def test_ip_address(self):
        """Test IP address URL."""
        result = validate_url("http://192.168.1.1")
        assert result == "http://192.168.1.1"

    def test_empty_url(self):
        """Test empty URL raises error."""
        with pytest.raises(ValidationError) as exc_info:
            validate_url("")
        assert "empty" in str(exc_info.value).lower()

    def test_http_not_allowed(self):
        """Test HTTP not allowed when specified."""
        with pytest.raises(ValidationError) as exc_info:
            validate_url("http://example.com", allow_http=False)
        assert "HTTPS" in str(exc_info.value)


class TestValidateFilePath:
    """Tests for file path validation."""

    def test_valid_path(self, tmp_path):
        """Test valid path."""
        result = validate_file_path(str(tmp_path / "test.json"))
        assert isinstance(result, Path)

    def test_must_exist_when_exists(self, tmp_path):
        """Test must_exist with existing file."""
        f = tmp_path / "exists.txt"
        f.write_text("test")
        result = validate_file_path(str(f), must_exist=True)
        assert result == f

    def test_must_exist_when_not_exists(self, tmp_path):
        """Test must_exist with non-existent file."""
        with pytest.raises(ValidationError) as exc_info:
            validate_file_path(str(tmp_path / "nonexistent.txt"), must_exist=True)
        assert "not found" in str(exc_info.value).lower()

    def test_create_parent(self, tmp_path):
        """Test create_parent creates directories."""
        path = tmp_path / "new" / "nested" / "file.txt"
        result = validate_file_path(str(path), create_parent=True)
        assert result == path
        assert path.parent.exists()
        assert path.parent.is_dir()

    def test_empty_path(self):
        """Test empty path raises error."""
        with pytest.raises(ValidationError):
            validate_file_path("")


class TestValidateFormat:
    """Tests for format validation."""

    def test_valid_json_format(self):
        """Test valid JSON format."""
        assert validate_format("json") == "json"
        assert validate_format("JSON") == "json"

    def test_valid_jsonl_format(self):
        """Test valid JSONL format."""
        assert validate_format("jsonl") == "jsonl"

    def test_valid_csv_format(self):
        """Test valid CSV format."""
        assert validate_format("csv") == "csv"

    def test_invalid_format(self):
        """Test invalid format raises error."""
        with pytest.raises(ValidationError) as exc_info:
            validate_format("xml")
        assert "invalid format" in str(exc_info.value).lower()

    def test_custom_allowed(self):
        """Test custom allowed formats."""
        result = validate_format("yaml", allowed=["yaml", "toml"])
        assert result == "yaml"


class TestValidateSelector:
    """Tests for CSS selector validation."""

    def test_valid_selector(self):
        """Test valid selector."""
        assert validate_selector("div.class") == "div.class"
        assert validate_selector("#id") == "#id"
        assert validate_selector("div > p") == "div > p"

    def test_empty_selector(self):
        """Test empty selector raises error."""
        with pytest.raises(ValidationError):
            validate_selector("")

    def test_selector_too_long(self):
        """Test selector too long raises error."""
        with pytest.raises(ValidationError) as exc_info:
            validate_selector("a" * 501)
        assert "too long" in str(exc_info.value).lower()

    def test_invalid_selector_html_tags(self):
        """Test selector with HTML tags raises error."""
        with pytest.raises(ValidationError):
            validate_selector("<div>test</div>")


class TestValidateTimeout:
    """Tests for timeout validation."""

    def test_valid_timeout(self):
        """Test valid timeout."""
        assert validate_timeout(30.0) == 30.0
        assert validate_timeout(1) == 1

    def test_zero_timeout(self):
        """Test zero timeout raises error."""
        with pytest.raises(ValidationError):
            validate_timeout(0)

    def test_negative_timeout(self):
        """Test negative timeout raises error."""
        with pytest.raises(ValidationError):
            validate_timeout(-5)

    def test_timeout_too_large(self):
        """Test timeout exceeding max raises error."""
        with pytest.raises(ValidationError) as exc_info:
            validate_timeout(500)
        assert "300" in str(exc_info.value)
