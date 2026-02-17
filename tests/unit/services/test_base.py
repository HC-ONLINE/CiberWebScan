"""
Tests for BaseService class.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ciberwebscan.services.base import (
    BaseService,
    ExecutionError,
    ServiceError,
    ServiceResult,
    ValidationError,
)

# =============================================================================
# Fixtures
# =============================================================================


class ConcreteService(BaseService):
    """Concrete implementation for testing."""

    def do_something(self, value: str) -> ServiceResult[str]:
        """Test method."""
        result = ServiceResult[str](success=True, data=f"processed: {value}")
        return result.finalize()


@pytest.fixture
def service() -> ConcreteService:
    """Create a test service instance."""
    return ConcreteService()


# =============================================================================
# ServiceResult Tests
# =============================================================================


class TestServiceResult:
    """Tests for ServiceResult dataclass."""

    def test_result_success(self):
        """Test successful result creation."""
        result = ServiceResult[str](success=True, data="test")
        assert result.success is True
        assert result.data == "test"
        assert result.error is None
        assert result.error_code is None

    def test_result_failure(self):
        """Test failure result creation."""
        result = ServiceResult[str](
            success=False,
            error="Something went wrong",
            error_code="TEST_ERROR",
        )
        assert result.success is False
        assert result.data is None
        assert result.error == "Something went wrong"
        assert result.error_code == "TEST_ERROR"

    def test_result_with_warnings(self):
        """Test result with warnings."""
        result = ServiceResult[dict](
            success=True,
            data={"key": "value"},
            warnings=["Warning 1", "Warning 2"],
        )
        assert result.success is True
        assert len(result.warnings) == 2

    def test_result_with_export_info(self):
        """Test result with export information."""
        result = ServiceResult[list](
            success=True,
            data=[1, 2, 3],
            exported=True,
            export_path=Path("/tmp/export.json"),
            export_format="json",
        )
        assert result.exported is True
        assert result.export_path == Path("/tmp/export.json")
        assert result.export_format == "json"

    def test_result_finalize(self):
        """Test result finalization."""
        result = ServiceResult[str](success=True, data="test")
        finalized = result.finalize()
        assert finalized is result
        assert finalized.finished_at is not None
        assert finalized.duration_seconds >= 0

    def test_ok_factory(self):
        """Test ok factory method."""
        result = ServiceResult.ok("success data")
        assert result.success is True
        assert result.data == "success data"

    def test_fail_factory(self):
        """Test fail factory method."""
        result = ServiceResult.fail("error message", "ERR_CODE")
        assert result.success is False
        assert result.error == "error message"
        assert result.error_code == "ERR_CODE"


# =============================================================================
# Exception Tests
# =============================================================================


class TestServiceExceptions:
    """Tests for service exceptions."""

    def test_service_error(self):
        """Test base ServiceError."""
        error = ServiceError("Test error")
        assert str(error) == "Test error"
        assert error.code == "SERVICE_ERROR"

    def test_service_error_with_code(self):
        """Test ServiceError with custom code."""
        error = ServiceError("Test error", code="CUSTOM_CODE")
        assert error.code == "CUSTOM_CODE"

    def test_validation_error(self):
        """Test ValidationError."""
        error = ValidationError("Invalid input")
        assert str(error) == "Invalid input"
        assert error.code == "VALIDATION_ERROR"

    def test_execution_error(self):
        """Test ExecutionError."""
        error = ExecutionError("Execution failed")
        assert str(error) == "Execution failed"
        assert error.code == "EXECUTION_ERROR"


# =============================================================================
# BaseService Tests
# =============================================================================


class TestBaseService:
    """Tests for BaseService class."""

    def test_service_creation(self, service: ConcreteService):
        """Test service instantiation."""
        assert service is not None
        assert service.logger is not None

    def test_validate_url_valid(self, service: ConcreteService):
        """Test URL validation with valid URL."""
        url = service._validate_url("https://example.com")
        assert url == "https://example.com"

    def test_validate_url_without_scheme(self, service: ConcreteService):
        """Test URL validation adds scheme."""
        url = service._validate_url("example.com")
        assert url.startswith("https://")

    def test_validate_url_invalid(self, service: ConcreteService):
        """Test URL validation with invalid URL."""
        with pytest.raises(ValidationError):
            service._validate_url("")

    def test_validate_url_with_path(self, service: ConcreteService):
        """Test URL validation preserves path."""
        url = service._validate_url("https://example.com/path/to/page")
        assert url == "https://example.com/path/to/page"

    def test_do_something(self, service: ConcreteService):
        """Test concrete implementation."""
        result = service.do_something("test")
        assert result.success is True
        assert result.data == "processed: test"


# =============================================================================
# Export Tests
# =============================================================================


class TestServiceExport:
    """Tests for service export functionality."""

    def test_export_result_json(self, service: ConcreteService, tmp_path: Path):
        """Test exporting result as JSON."""
        data = {"key": "value", "numbers": [1, 2, 3]}
        output_path = tmp_path / "output.json"

        exported, path = service._export_result(data, str(output_path), "json")

        assert exported is True
        assert path.exists()
        assert path.suffix == ".json"

        # Verify content - exporter wraps items in a structure
        import json

        with open(path) as f:
            loaded = json.load(f)
        # Data is wrapped in 'items' list by JSONExporter
        assert "items" in loaded
        assert loaded["items"][0] == data

    def test_export_result_jsonl(self, service: ConcreteService, tmp_path: Path):
        """Test exporting result as JSONL."""
        data = [{"id": 1}, {"id": 2}, {"id": 3}]
        output_path = tmp_path / "output.jsonl"

        exported, path = service._export_result(data, str(output_path), "jsonl")

        assert exported is True
        assert path.exists()
        assert path.suffix == ".jsonl"

    def test_export_result_csv(self, service: ConcreteService, tmp_path: Path):
        """Test exporting result as CSV."""
        data = [
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25},
        ]
        output_path = tmp_path / "output.csv"

        exported, path = service._export_result(data, str(output_path), "csv")

        assert exported is True
        assert path.exists()
        assert path.suffix == ".csv"

    def test_export_result_creates_directory(
        self, service: ConcreteService, tmp_path: Path
    ):
        """Test that export creates parent directories."""
        data = {"test": True}
        output_path = tmp_path / "subdir" / "nested" / "output.json"

        exported, path = service._export_result(data, str(output_path), "json")

        assert exported is True
        assert path.exists()
        assert path.parent.exists()

    def test_export_result_pydantic_model(
        self, service: ConcreteService, tmp_path: Path
    ):
        """Test exporting Pydantic model."""
        from pydantic import BaseModel

        class TestModel(BaseModel):
            name: str
            value: int

        data = TestModel(name="test", value=42)
        output_path = tmp_path / "model.json"

        exported, path = service._export_result(data, str(output_path), "json")

        assert exported is True

        import json

        with open(path) as f:
            loaded = json.load(f)
        # Data wrapped in 'items' list
        assert "items" in loaded
        assert loaded["items"][0]["name"] == "test"
        assert loaded["items"][0]["value"] == 42

    @pytest.mark.parametrize("fmt", ["json", "jsonl", "csv"])
    def test_export_passes_include_raw_from_config(
        self, service: ConcreteService, tmp_path: Path, fmt: str
    ):
        """_export_result reads include_raw_html from config and forwards it."""
        from unittest.mock import Mock, patch

        data = [{"name": "Alice"}]
        output_path = tmp_path / f"output.{fmt}"

        with (
            patch("ciberwebscan.services.base.get_config") as mock_cfg,
            patch("ciberwebscan.services.base.JSONExporter") as mock_json,
            patch("ciberwebscan.services.base.JSONLExporter") as mock_jsonl,
            patch("ciberwebscan.services.base.CSVExporter") as mock_csv,
        ):
            mock_cfg.return_value = Mock(
                export=Mock(pretty=True, include_raw_html=True, buffer_size=256)
            )
            mock_exp = Mock()
            mock_exp.__enter__ = Mock(return_value=mock_exp)
            mock_exp.__exit__ = Mock(return_value=False)
            mocks = {"json": mock_json, "jsonl": mock_jsonl, "csv": mock_csv}
            mocks[fmt].return_value = mock_exp

            service._export_result(data, str(output_path), fmt)

            call_kwargs = mocks[fmt].call_args.kwargs
            assert call_kwargs["include_raw"] is True
            assert mock_exp.buffer_size == 256

    @pytest.mark.parametrize("fmt", ["json", "jsonl", "csv"])
    def test_export_passes_buffer_size_from_config(
        self, service: ConcreteService, tmp_path: Path, fmt: str
    ):
        """_export_result reads buffer_size from config and sets it on exporter."""
        from unittest.mock import Mock, patch

        data = {"key": "value"}
        output_path = tmp_path / f"out.{fmt}"

        with (
            patch("ciberwebscan.services.base.get_config") as mock_cfg,
            patch("ciberwebscan.services.base.JSONExporter") as mock_json,
            patch("ciberwebscan.services.base.JSONLExporter") as mock_jsonl,
            patch("ciberwebscan.services.base.CSVExporter") as mock_csv,
        ):
            mock_cfg.return_value = Mock(
                export=Mock(pretty=False, include_raw_html=False, buffer_size=512)
            )
            mock_exp = Mock()
            mock_exp.__enter__ = Mock(return_value=mock_exp)
            mock_exp.__exit__ = Mock(return_value=False)
            mocks = {"json": mock_json, "jsonl": mock_jsonl, "csv": mock_csv}
            mocks[fmt].return_value = mock_exp

            service._export_result(data, str(output_path), fmt)

            assert mock_exp.buffer_size == 512

    def test_export_include_raw_false_by_default(
        self, service: ConcreteService, tmp_path: Path
    ):
        """include_raw defaults to False when config says so."""
        from unittest.mock import Mock, patch

        data = {"key": "value"}
        output_path = tmp_path / "out.json"

        with (
            patch("ciberwebscan.services.base.get_config") as mock_cfg,
            patch("ciberwebscan.services.base.JSONExporter") as mock_json,
        ):
            mock_cfg.return_value = Mock(
                export=Mock(pretty=True, include_raw_html=False, buffer_size=100)
            )
            mock_exp = Mock()
            mock_exp.__enter__ = Mock(return_value=mock_exp)
            mock_exp.__exit__ = Mock(return_value=False)
            mock_json.return_value = mock_exp

            service._export_result(data, str(output_path), "json")

            assert mock_json.call_args.kwargs["include_raw"] is False
