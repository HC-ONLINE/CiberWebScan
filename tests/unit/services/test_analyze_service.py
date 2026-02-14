"""
Tests for AnalyzeService class.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ciberwebscan.export.models import (
    FingerprintResult,
    SSLResult,
    TechnologyMatch,
)
from ciberwebscan.services.analyze_service import (
    AnalyzeOptions,
    AnalyzeService,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def analyze_service() -> AnalyzeService:
    """Create a test analyze service."""
    return AnalyzeService()


@pytest.fixture
def mock_ssl_result() -> SSLResult:
    """Create a mock SSL result."""
    return SSLResult(
        is_https=True,
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        certificate=None,
        chain_valid=True,
        findings=[],
        grade="A",
    )


@pytest.fixture
def mock_fingerprint_result() -> FingerprintResult:
    """Create a mock fingerprint result."""
    return FingerprintResult(
        technologies=[
            TechnologyMatch(name="nginx", version="1.20", category="web-server"),
            TechnologyMatch(name="PHP", version="8.1", category="language"),
        ],
        server="nginx/1.20",
        powered_by="PHP/8.1",
    )


# =============================================================================
# AnalyzeOptions Tests
# =============================================================================


class TestAnalyzeOptions:
    """Tests for AnalyzeOptions dataclass."""

    def test_default_options(self):
        """Test default option values."""
        options = AnalyzeOptions(url="https://example.com")

        assert options.url == "https://example.com"
        assert options.ssl is True
        assert options.fingerprint is True
        assert options.cve is True
        assert options.export is None

    def test_custom_options(self):
        """Test custom option values."""
        options = AnalyzeOptions(
            url="https://example.com",
            ssl=True,
            fingerprint=False,
            cve=False,
            export="report.json",
            cve_sources=["nvd", "vulners"],
        )

        assert options.ssl is True
        assert options.fingerprint is False
        assert options.cve is False
        assert options.export == "report.json"
        assert "vulners" in options.cve_sources


# =============================================================================
# AnalyzeService Tests
# =============================================================================


class TestAnalyzeService:
    """Tests for AnalyzeService class."""

    def test_service_creation(self, analyze_service: AnalyzeService):
        """Test service instantiation."""
        assert analyze_service is not None
        assert analyze_service._ssl_analyzer is None  # Lazy loaded
        assert analyze_service._fingerprinter is None

    def test_ssl_analyzer_property(self, analyze_service: AnalyzeService):
        """Test lazy loading of SSL analyzer."""
        analyzer = analyze_service.ssl_analyzer
        assert analyzer is not None
        # Same instance on second access
        assert analyzer is analyze_service.ssl_analyzer

    def test_fingerprinter_property(self, analyze_service: AnalyzeService):
        """Test lazy loading of fingerprinter."""
        fingerprinter = analyze_service.fingerprinter
        assert fingerprinter is not None
        assert fingerprinter is analyze_service.fingerprinter

    def test_cve_aggregator_property(self, analyze_service: AnalyzeService):
        """Test lazy loading of CVE aggregator."""
        aggregator = analyze_service.cve_aggregator
        assert aggregator is not None
        assert aggregator is analyze_service.cve_aggregator

    @patch("ciberwebscan.core.client.http_client.HTTPClient")
    @patch("ciberwebscan.services.analyze_service.get_config")
    def test_fingerprint_uses_http_config_timeout_when_default(
        self,
        mock_get_config: Mock,
        mock_http_client: Mock,
    ):
        """Test fingerprint request timeout uses global config default."""
        http_config = Mock(timeout=Mock(read=44.0, connect=12.0))
        mock_get_config.return_value = Mock(
            http=http_config, user_agent=Mock(mode="static", custom="TestAgent")
        )

        mock_response = Mock(headers={}, text="<html></html>")
        mock_client = Mock()
        mock_client.get.return_value = mock_response
        mock_http_client.return_value.__enter__.return_value = mock_client

        service = AnalyzeService()
        service._fingerprinter = Mock()
        service._fingerprinter.fingerprint.return_value = {"technologies": {}}
        service._fingerprint(
            "https://example.com", AnalyzeOptions(url="https://example.com")
        )

        assert mock_http_client.call_args is not None
        assert mock_http_client.call_args.kwargs["timeout"] == 44.0


# =============================================================================
# Analysis Tests
# =============================================================================


class TestAnalyze:
    """Tests for analyze method."""

    @patch.object(AnalyzeService, "_analyze_ssl")
    @patch.object(AnalyzeService, "_fingerprint")
    @patch.object(AnalyzeService, "_lookup_cves")
    def test_analyze_full(
        self,
        mock_cves: Mock,
        mock_fp: Mock,
        mock_ssl: Mock,
        analyze_service: AnalyzeService,
        mock_ssl_result: SSLResult,
        mock_fingerprint_result: FingerprintResult,
    ):
        """Test full analysis."""
        mock_ssl.return_value = mock_ssl_result
        mock_fp.return_value = mock_fingerprint_result
        mock_cves.return_value = []

        options = AnalyzeOptions(url="https://example.com")
        result = analyze_service.analyze(options)

        assert result.success is True
        assert result.data is not None
        assert result.data.ssl is not None
        assert result.data.fingerprint is not None
        mock_ssl.assert_called_once()
        mock_fp.assert_called_once()

    @patch.object(AnalyzeService, "_analyze_ssl")
    def test_analyze_ssl_only(
        self,
        mock_ssl: Mock,
        analyze_service: AnalyzeService,
        mock_ssl_result: SSLResult,
    ):
        """Test SSL-only analysis."""
        mock_ssl.return_value = mock_ssl_result

        options = AnalyzeOptions(
            url="https://example.com",
            ssl=True,
            fingerprint=False,
            cve=False,
        )
        result = analyze_service.analyze(options)

        assert result.success is True
        assert result.data.ssl is not None
        assert result.data.fingerprint is None

    @patch.object(AnalyzeService, "_fingerprint")
    def test_analyze_fingerprint_only(
        self,
        mock_fp: Mock,
        analyze_service: AnalyzeService,
        mock_fingerprint_result: FingerprintResult,
    ):
        """Test fingerprint-only analysis."""
        mock_fp.return_value = mock_fingerprint_result

        options = AnalyzeOptions(
            url="https://example.com",
            ssl=False,
            fingerprint=True,
            cve=False,
        )
        result = analyze_service.analyze(options)

        assert result.success is True
        assert result.data.ssl is None
        assert result.data.fingerprint is not None

    def test_analyze_invalid_url(self, analyze_service: AnalyzeService):
        """Test analysis with invalid URL."""
        options = AnalyzeOptions(url="")
        result = analyze_service.analyze(options)

        assert result.success is False
        assert result.error_code == "VALIDATION_ERROR"

    @patch.object(AnalyzeService, "_analyze_ssl")
    @patch.object(AnalyzeService, "_fingerprint")
    def test_analyze_with_export(
        self,
        mock_fp: Mock,
        mock_ssl: Mock,
        analyze_service: AnalyzeService,
        mock_ssl_result: SSLResult,
        mock_fingerprint_result: FingerprintResult,
        tmp_path: Path,
    ):
        """Test analysis with export."""
        mock_ssl.return_value = mock_ssl_result
        mock_fp.return_value = mock_fingerprint_result

        output_file = tmp_path / "report.json"
        options = AnalyzeOptions(
            url="https://example.com",
            ssl=True,
            fingerprint=True,
            cve=False,
            export=str(output_file),
        )
        result = analyze_service.analyze(options)

        assert result.success is True
        assert result.exported is True
        assert result.export_path is not None


# =============================================================================
# Individual Analysis Tests
# =============================================================================


class TestAnalyzeSSL:
    """Tests for analyze_ssl method."""

    @patch.object(AnalyzeService, "_analyze_ssl")
    def test_analyze_ssl(
        self,
        mock_ssl: Mock,
        analyze_service: AnalyzeService,
        mock_ssl_result: SSLResult,
    ):
        """Test standalone SSL analysis."""
        mock_ssl.return_value = mock_ssl_result

        result = analyze_service.analyze_ssl("https://example.com")

        assert result.success is True
        assert result.data is not None


class TestFingerprint:
    """Tests for fingerprint_url method."""

    @patch.object(AnalyzeService, "_fingerprint")
    def test_fingerprint_url(
        self,
        mock_fp: Mock,
        analyze_service: AnalyzeService,
        mock_fingerprint_result: FingerprintResult,
    ):
        """Test standalone fingerprinting."""
        mock_fp.return_value = mock_fingerprint_result

        result = analyze_service.fingerprint_url("https://example.com")

        assert result.success is True
        assert result.data is not None
        assert len(result.data.technologies) == 2

    @patch.object(AnalyzeService, "_fingerprint")
    def test_fingerprint_url_deep(
        self,
        mock_fp: Mock,
        analyze_service: AnalyzeService,
        mock_fingerprint_result: FingerprintResult,
    ):
        """Test deep fingerprinting."""
        mock_fp.return_value = mock_fingerprint_result

        result = analyze_service.fingerprint_url(
            "https://example.com",
            deep=True,
        )

        assert result.success is True


class TestLookupCVEs:
    """Tests for lookup_cves method."""

    @patch.object(AnalyzeService, "_lookup_cves")
    def test_lookup_cves_from_matches(
        self,
        mock_cves: Mock,
        analyze_service: AnalyzeService,
    ):
        """Test CVE lookup from TechnologyMatch list."""
        mock_cves.return_value = []

        technologies = [
            TechnologyMatch(name="nginx", version="1.20"),
            TechnologyMatch(name="PHP", version="8.1"),
        ]
        result = analyze_service.lookup_cves(technologies)

        assert result.success is True
        mock_cves.assert_called_once()

    @patch.object(AnalyzeService, "_lookup_cves")
    def test_lookup_cves_from_strings(
        self,
        mock_cves: Mock,
        analyze_service: AnalyzeService,
    ):
        """Test CVE lookup from string list."""
        mock_cves.return_value = []

        result = analyze_service.lookup_cves(["nginx", "PHP"])

        assert result.success is True
        mock_cves.assert_called_once()
