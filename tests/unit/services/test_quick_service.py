"""
Tests for QuickService class.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ciberwebscan.export.models import AnalysisReport
from ciberwebscan.services.quick_service import PRESETS, QuickOptions, QuickService

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def quick_service() -> QuickService:
    """Create a test quick service."""
    return QuickService()


@pytest.fixture
def mock_analyze_result():
    """Create a mock analyze service result."""
    result = MagicMock()
    result.success = True
    result.data = AnalysisReport()
    return result


@pytest.fixture
def mock_attack_result():
    """Create a mock attack service result."""
    result = MagicMock()
    result.success = True
    result.data = MagicMock()
    return result


@pytest.fixture
def mock_scrape_result():
    """Create a mock scrape service result."""
    result = MagicMock()
    result.success = True
    result.data = MagicMock()
    return result


# =============================================================================
# QuickOptions Tests
# =============================================================================


class TestQuickOptions:
    """Tests for QuickOptions dataclass."""

    def test_default_options(self):
        """Test default option values."""
        options = QuickOptions(url="https://example.com")

        assert options.url == "https://example.com"
        assert options.preset == "low"
        assert options.consent is False
        assert options.selector is None
        assert options.dynamic is False

    def test_custom_options(self):
        """Test custom option values."""
        options = QuickOptions(
            url="https://example.com",
            preset="high",
            consent=True,
            selector=".content",
            dynamic=True,
            timeout=60.0,
            proxy="http://proxy:8080",
        )

        assert options.preset == "high"
        assert options.consent is True
        assert options.selector == ".content"
        assert options.dynamic is True
        assert options.timeout == 60.0
        assert options.proxy == "http://proxy:8080"


# =============================================================================
# Presets Tests
# =============================================================================


class TestPresets:
    """Tests for PRESETS configuration."""

    def test_presets_contain_all_levels(self):
        """Test that all three preset levels exist."""
        assert "low" in PRESETS
        assert "medium" in PRESETS
        assert "high" in PRESETS

    def test_low_preset_no_attacks(self):
        """Test that low preset has no attacks."""
        assert PRESETS["low"]["attack"] is None

    def test_medium_preset_has_attacks(self):
        """Test that medium preset has attacks."""
        assert PRESETS["medium"]["attack"] is not None
        assert PRESETS["medium"]["attack"]["xss"] is True
        assert PRESETS["medium"]["attack"]["sqli"] is True
        assert PRESETS["medium"]["attack"]["traversal"] is False
        assert PRESETS["medium"]["attack"]["enumeration"] is False

    def test_high_preset_all_attacks(self):
        """Test that high preset has all attacks."""
        assert PRESETS["high"]["attack"] is not None
        assert PRESETS["high"]["attack"]["xss"] is True
        assert PRESETS["high"]["attack"]["sqli"] is True
        assert PRESETS["high"]["attack"]["traversal"] is True
        assert PRESETS["high"]["attack"]["enumeration"] is True
        assert PRESETS["high"]["attack"]["intensity"] == "high"

    def test_preset_structure(self):
        """Test that each preset has required keys."""
        for name, preset in PRESETS.items():
            assert "analyze" in preset, f"Preset '{name}' missing 'analyze'"
            assert "attack" in preset, f"Preset '{name}' missing 'attack'"
            assert "scrape" in preset, f"Preset '{name}' missing 'scrape'"

    def test_analyze_options_have_ssl_fingerprint_headers(self):
        """Test that analyze options include required fields."""
        for name, preset in PRESETS.items():
            analyze = preset["analyze"]
            assert "ssl" in analyze, f"Preset '{name}' missing ssl"
            assert "fingerprint" in analyze, f"Preset '{name}' missing fingerprint"
            assert "analyze_headers" in analyze, (
                f"Preset '{name}' missing analyze_headers"
            )


# =============================================================================
# QuickService Tests
# =============================================================================


class TestQuickServiceCreation:
    """Tests for QuickService instantiation."""

    def test_service_creation(self, quick_service: QuickService):
        """Test service instantiation."""
        assert quick_service is not None
        assert quick_service._analyze_service is None
        assert quick_service._attack_service is None
        assert quick_service._scrape_service is None

    def test_analyze_service_lazy_loaded(self, quick_service: QuickService):
        """Test lazy loading of analyze service."""
        service = quick_service.analyze_service
        assert service is not None
        assert service is quick_service.analyze_service

    def test_attack_service_lazy_loaded(self, quick_service: QuickService):
        """Test lazy loading of attack service."""
        service = quick_service.attack_service
        assert service is not None
        assert service is quick_service.attack_service

    def test_scrape_service_lazy_loaded(self, quick_service: QuickService):
        """Test lazy loading of scrape service."""
        service = quick_service.scrape_service
        assert service is not None
        assert service is quick_service.scrape_service


# =============================================================================
# QuickScan Validation Tests
# =============================================================================


class TestQuickScanValidation:
    """Tests for quick_scan validation."""

    def test_invalid_preset(self, quick_service: QuickService):
        """Test invalid preset raises ValidationError."""
        options = QuickOptions(url="https://example.com", preset="invalid")

        with pytest.raises(Exception) as exc_info:
            quick_service.quick_scan(options)

        assert "Invalid preset" in str(exc_info.value)

    def test_medium_without_consent(self, quick_service: QuickService):
        """Test medium preset without consent raises ValidationError."""
        options = QuickOptions(
            url="https://example.com", preset="medium", consent=False
        )

        with pytest.raises(Exception) as exc_info:
            quick_service.quick_scan(options)

        assert "consent" in str(exc_info.value).lower()

    def test_high_without_consent(self, quick_service: QuickService):
        """Test high preset without consent raises ValidationError."""
        options = QuickOptions(url="https://example.com", preset="high", consent=False)

        with pytest.raises(Exception) as exc_info:
            quick_service.quick_scan(options)

        assert "consent" in str(exc_info.value).lower()

    def test_invalid_url(self, quick_service: QuickService):
        """Test invalid URL raises ValidationError."""
        options = QuickOptions(url="")

        with pytest.raises(Exception) as exc_info:
            quick_service.quick_scan(options)

        assert "URL is required" in str(exc_info.value)


# =============================================================================
# QuickScan Execution Tests
# =============================================================================


class TestQuickScanExecution:
    """Tests for quick_scan execution."""

    @patch.object(QuickService, "_run_analysis")
    @patch.object(QuickService, "_run_attacks")
    @patch.object(QuickService, "_run_scrape")
    def test_low_preset_runs_analysis_only(
        self,
        mock_scrape: MagicMock,
        mock_attacks: MagicMock,
        mock_analysis: MagicMock,
        quick_service: QuickService,
    ):
        """Test low preset runs only analysis."""
        options = QuickOptions(url="https://example.com", preset="low")

        result = quick_service.quick_scan(options)

        assert result.success is True
        mock_analysis.assert_called_once()
        mock_attacks.assert_not_called()
        mock_scrape.assert_not_called()

    @patch.object(QuickService, "_run_analysis")
    @patch.object(QuickService, "_run_attacks")
    @patch.object(QuickService, "_run_scrape")
    def test_medium_preset_runs_analysis_and_attacks(
        self,
        mock_scrape: MagicMock,
        mock_attacks: MagicMock,
        mock_analysis: MagicMock,
        quick_service: QuickService,
    ):
        """Test medium preset runs analysis and attacks."""
        options = QuickOptions(url="https://example.com", preset="medium", consent=True)

        result = quick_service.quick_scan(options)

        assert result.success is True
        mock_analysis.assert_called_once()
        mock_attacks.assert_called_once()
        mock_scrape.assert_not_called()

    @patch.object(QuickService, "_run_analysis")
    @patch.object(QuickService, "_run_attacks")
    @patch.object(QuickService, "_run_scrape")
    def test_high_preset_runs_all(
        self,
        mock_scrape: MagicMock,
        mock_attacks: MagicMock,
        mock_analysis: MagicMock,
        quick_service: QuickService,
    ):
        """Test high preset runs analysis, attacks, and scrape if dynamic."""
        options = QuickOptions(
            url="https://example.com", preset="high", consent=True, dynamic=True
        )

        result = quick_service.quick_scan(options)

        assert result.success is True
        mock_analysis.assert_called_once()
        mock_attacks.assert_called_once()
        mock_scrape.assert_called_once()

    @patch.object(QuickService, "_run_analysis")
    @patch.object(QuickService, "_run_scrape")
    def test_selector_enables_scraping(
        self,
        mock_scrape: MagicMock,
        mock_analysis: MagicMock,
        quick_service: QuickService,
    ):
        """Test that selector enables scraping even on low preset."""
        options = QuickOptions(
            url="https://example.com", preset="low", selector=".content"
        )

        result = quick_service.quick_scan(options)

        assert result.success is True
        mock_analysis.assert_called_once()
        mock_scrape.assert_called_once()


# =============================================================================
# Export Tests
# =============================================================================


class TestQuickScanExport:
    """Tests for quick_scan export functionality."""

    @patch.object(QuickService, "_run_analysis")
    @patch.object(QuickService, "_export_result")
    def test_export_called_when_output_specified(
        self,
        mock_export: MagicMock,
        mock_analysis: MagicMock,
        quick_service: QuickService,
        tmp_path: Path,
    ):
        """Test export is called when output is specified."""
        mock_export.return_value = (True, str(tmp_path / "report.json"))

        output_file = tmp_path / "report.json"
        options = QuickOptions(
            url="https://example.com",
            preset="low",
            output=str(output_file),
        )

        result = quick_service.quick_scan(options)

        assert result.success is True
        mock_export.assert_called_once()

    @patch.object(QuickService, "_run_analysis")
    def test_no_export_when_no_output(
        self,
        mock_analysis: MagicMock,
        quick_service: QuickService,
    ):
        """Test no export when output is not specified."""
        options = QuickOptions(url="https://example.com", preset="low")

        result = quick_service.quick_scan(options)

        assert result.success is True
        assert result.exported is False
