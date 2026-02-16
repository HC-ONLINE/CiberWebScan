"""
Tests for AnalyzeService class.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ciberwebscan.core.analyzers.cve.models import CVESource
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
        http_config = Mock(timeout=Mock(read=44.0, connect=12.0), proxy=None)
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


# =============================================================================
# Config Integration Tests
# =============================================================================


class TestAnalyzeServiceConfigIntegration:
    """Tests for configuration integration in AnalyzeService."""

    def test_ssl_analyzer_uses_config(self, analyze_service: AnalyzeService):
        """Test SSL analyzer is created with analysis.ssl config."""
        analyzer = analyze_service.ssl_analyzer
        cfg = analyze_service.app_config.analysis.ssl
        assert analyzer.check_expiry == cfg.check_expiry
        assert analyzer.check_chain == cfg.check_chain
        assert analyzer.check_revocation == cfg.check_revocation
        assert analyzer.warning_days == cfg.warning_days

    def test_fingerprinter_uses_config(self, analyze_service: AnalyzeService):
        """Test fingerprinter is created with analysis.fingerprint config."""
        fp = analyze_service.fingerprinter
        cfg = analyze_service.app_config.analysis.fingerprint
        assert fp.check_headers == cfg.check_headers
        assert fp.check_html == cfg.check_html
        assert fp.check_scripts == cfg.check_scripts
        assert fp.check_cookies == cfg.check_cookies
        assert fp.check_dns == cfg.check_dns

    def test_cve_aggregator_uses_config(self, analyze_service: AnalyzeService):
        """Test CVE aggregator is created with analysis.cve config."""
        aggregator = analyze_service.cve_aggregator
        cfg = analyze_service.app_config.analysis.cve
        assert aggregator.cache_ttl == cfg.cache_ttl

    def test_headers_analyzer_uses_config(self, analyze_service: AnalyzeService):
        """Test headers analyzer is created with analysis.headers config."""
        analyzer = analyze_service.headers_analyzer
        cfg = analyze_service.app_config.analysis.headers
        assert analyzer.required_headers == cfg.required_headers

    def test_resolve_cve_sources_nvd(self):
        """Test _resolve_cve_sources for 'nvd'."""
        sources = AnalyzeService._resolve_cve_sources("nvd")
        assert sources == [CVESource.NVD]

    def test_resolve_cve_sources_circl(self):
        """Test _resolve_cve_sources for 'circl'."""
        sources = AnalyzeService._resolve_cve_sources("circl")
        assert sources == [CVESource.CIRCL]

    def test_resolve_cve_sources_vulners(self):
        """Test _resolve_cve_sources for 'vulners'."""
        sources = AnalyzeService._resolve_cve_sources("vulners")
        assert sources == [CVESource.VULNERS]

    def test_resolve_cve_sources_all(self):
        """Test _resolve_cve_sources for 'all'."""
        sources = AnalyzeService._resolve_cve_sources("all")
        assert CVESource.NVD in sources
        assert CVESource.CIRCL in sources
        assert CVESource.VULNERS in sources

    def test_resolve_cve_sources_unknown_falls_back(self):
        """Test _resolve_cve_sources for unknown value."""
        sources = AnalyzeService._resolve_cve_sources("unknown")
        assert sources == [CVESource.NVD, CVESource.CIRCL]


class TestAnalyzeEnabledFlags:
    """Tests for analysis.*.enabled config flags."""

    @patch.object(AnalyzeService, "_analyze_ssl")
    @patch.object(AnalyzeService, "_fingerprint")
    @patch.object(AnalyzeService, "_lookup_cves")
    @patch.object(AnalyzeService, "_analyze_headers")
    def test_disabled_ssl_skips_ssl_analysis(
        self,
        mock_headers: Mock,
        mock_cves: Mock,
        mock_fp: Mock,
        mock_ssl: Mock,
    ):
        """Test that SSL analysis is skipped when config disabled."""
        with patch("ciberwebscan.services.analyze_service.get_config") as mock_cfg:
            cfg = mock_cfg.return_value
            cfg.analysis.ssl.enabled = False
            cfg.analysis.fingerprint.enabled = True
            cfg.analysis.headers.enabled = True
            cfg.analysis.cve.enabled = True
            cfg.http.timeout.connect = 10.0
            cfg.http.timeout.read = 30.0
            cfg.user_agent = Mock(mode="static", custom="TestAgent")

            service = AnalyzeService()
            mock_fp.return_value = None
            mock_headers.return_value = None

            options = AnalyzeOptions(url="https://example.com", ssl=True)
            result = service.analyze(options)

            assert result.success is True
            mock_ssl.assert_not_called()

    @patch.object(AnalyzeService, "_analyze_ssl")
    @patch.object(AnalyzeService, "_fingerprint")
    @patch.object(AnalyzeService, "_lookup_cves")
    @patch.object(AnalyzeService, "_analyze_headers")
    def test_disabled_fingerprint_skips_fingerprinting(
        self,
        mock_headers: Mock,
        mock_cves: Mock,
        mock_fp: Mock,
        mock_ssl: Mock,
    ):
        """Test that fingerprinting is skipped when config disabled."""
        with patch("ciberwebscan.services.analyze_service.get_config") as mock_cfg:
            cfg = mock_cfg.return_value
            cfg.analysis.ssl.enabled = True
            cfg.analysis.fingerprint.enabled = False
            cfg.analysis.headers.enabled = True
            cfg.analysis.cve.enabled = True
            cfg.http.timeout.connect = 10.0
            cfg.http.timeout.read = 30.0
            cfg.user_agent = Mock(mode="static", custom="TestAgent")

            service = AnalyzeService()
            mock_ssl.return_value = None
            mock_headers.return_value = None

            options = AnalyzeOptions(url="https://example.com", fingerprint=True)
            result = service.analyze(options)

            assert result.success is True
            mock_fp.assert_not_called()

    @patch.object(AnalyzeService, "_analyze_ssl")
    @patch.object(AnalyzeService, "_fingerprint")
    @patch.object(AnalyzeService, "_lookup_cves")
    @patch.object(AnalyzeService, "_analyze_headers")
    def test_disabled_headers_skips_headers_analysis(
        self,
        mock_headers: Mock,
        mock_cves: Mock,
        mock_fp: Mock,
        mock_ssl: Mock,
    ):
        """Test that headers analysis is skipped when config disabled."""
        with patch("ciberwebscan.services.analyze_service.get_config") as mock_cfg:
            cfg = mock_cfg.return_value
            cfg.analysis.ssl.enabled = True
            cfg.analysis.fingerprint.enabled = True
            cfg.analysis.headers.enabled = False
            cfg.analysis.cve.enabled = True
            cfg.http.timeout.connect = 10.0
            cfg.http.timeout.read = 30.0
            cfg.user_agent = Mock(mode="static", custom="TestAgent")

            service = AnalyzeService()
            mock_ssl.return_value = None
            mock_fp.return_value = None

            options = AnalyzeOptions(url="https://example.com", analyze_headers=True)
            result = service.analyze(options)

            assert result.success is True
            mock_headers.assert_not_called()

    def test_analyze_options_has_headers_flag(self):
        """Test that AnalyzeOptions includes the analyze_headers flag."""
        options = AnalyzeOptions(url="https://example.com")
        assert options.analyze_headers is True

        options2 = AnalyzeOptions(url="https://example.com", analyze_headers=False)
        assert options2.analyze_headers is False


# =============================================================================
# Proxy Rotation Tests
# =============================================================================


class TestAnalyzeServiceProxyRotation:
    """Tests for proxy rotation integration in AnalyzeService."""

    @patch("ciberwebscan.services.analyze_service.get_config")
    def test_build_proxy_rotator_returns_none_when_no_proxy_config(
        self, mock_get_config: Mock
    ):
        """Rotator is None when proxy config is None."""
        mock_get_config.return_value = Mock(
            http=Mock(proxy=None),
            user_agent=Mock(mode="static", custom="TestAgent"),
            analysis=Mock(
                ssl=Mock(
                    enabled=True,
                    check_expiry=True,
                    check_chain=True,
                    check_revocation=False,
                    warning_days=30,
                ),
                fingerprint=Mock(
                    enabled=True,
                    check_headers=True,
                    check_html=True,
                    check_scripts=True,
                    check_cookies=True,
                    check_dns=True,
                ),
                cve=Mock(enabled=True, cache_ttl=3600),
                headers=Mock(enabled=True, required_headers=[]),
            ),
        )
        service = AnalyzeService()
        assert service._proxy_rotator is None

    @patch("ciberwebscan.services.analyze_service.get_config")
    def test_build_proxy_rotator_returns_none_when_rotate_disabled(
        self, mock_get_config: Mock
    ):
        """Rotator is None when proxy.rotate is False."""
        mock_get_config.return_value = Mock(
            http=Mock(proxy=Mock(rotate=False)),
            user_agent=Mock(mode="static", custom="TestAgent"),
            analysis=Mock(
                ssl=Mock(
                    enabled=True,
                    check_expiry=True,
                    check_chain=True,
                    check_revocation=False,
                    warning_days=30,
                ),
                fingerprint=Mock(
                    enabled=True,
                    check_headers=True,
                    check_html=True,
                    check_scripts=True,
                    check_cookies=True,
                    check_dns=True,
                ),
                cve=Mock(enabled=True, cache_ttl=3600),
                headers=Mock(enabled=True, required_headers=[]),
            ),
        )
        service = AnalyzeService()
        assert service._proxy_rotator is None

    @patch("ciberwebscan.services.analyze_service.get_config")
    def test_build_proxy_rotator_creates_rotator_with_proxy_list(
        self, mock_get_config: Mock
    ):
        """Rotator is created from proxy_list when present."""
        mock_get_config.return_value = Mock(
            http=Mock(
                proxy=Mock(
                    rotate=True,
                    proxy_list=["http://p1:8080", "http://p2:8080"],
                    rotation_interval=3,
                )
            ),
            user_agent=Mock(mode="static", custom="TestAgent"),
            analysis=Mock(
                ssl=Mock(
                    enabled=True,
                    check_expiry=True,
                    check_chain=True,
                    check_revocation=False,
                    warning_days=30,
                ),
                fingerprint=Mock(
                    enabled=True,
                    check_headers=True,
                    check_html=True,
                    check_scripts=True,
                    check_cookies=True,
                    check_dns=True,
                ),
                cve=Mock(enabled=True, cache_ttl=3600),
                headers=Mock(enabled=True, required_headers=[]),
            ),
        )
        service = AnalyzeService()
        assert service._proxy_rotator is not None
        assert service._proxy_rotator.proxies == [
            "http://p1:8080",
            "http://p2:8080",
        ]
        assert service._proxy_rotator.rotation_interval == 3

    @patch("ciberwebscan.services.analyze_service.get_config")
    def test_build_proxy_rotator_falls_back_to_individual_fields(
        self, mock_get_config: Mock
    ):
        """Rotator uses http/https/socks5 fields when proxy_list is empty."""
        mock_get_config.return_value = Mock(
            http=Mock(
                proxy=Mock(
                    rotate=True,
                    proxy_list=None,
                    http="http://proxy:8080",
                    https="https://proxy:8443",
                    socks5="socks5://proxy:1080",
                    rotation_interval=1,
                )
            ),
            user_agent=Mock(mode="static", custom="TestAgent"),
            analysis=Mock(
                ssl=Mock(
                    enabled=True,
                    check_expiry=True,
                    check_chain=True,
                    check_revocation=False,
                    warning_days=30,
                ),
                fingerprint=Mock(
                    enabled=True,
                    check_headers=True,
                    check_html=True,
                    check_scripts=True,
                    check_cookies=True,
                    check_dns=True,
                ),
                cve=Mock(enabled=True, cache_ttl=3600),
                headers=Mock(enabled=True, required_headers=[]),
            ),
        )
        service = AnalyzeService()
        assert service._proxy_rotator is not None
        assert len(service._proxy_rotator.proxies) == 3

    @patch("ciberwebscan.services.analyze_service.get_config")
    def test_build_proxy_rotator_returns_none_when_no_proxies(
        self, mock_get_config: Mock
    ):
        """Rotator is None when rotate=True but no proxies configured."""
        mock_get_config.return_value = Mock(
            http=Mock(
                proxy=Mock(
                    rotate=True,
                    proxy_list=None,
                    http=None,
                    https=None,
                    socks5=None,
                    rotation_interval=1,
                )
            ),
            user_agent=Mock(mode="static", custom="TestAgent"),
            analysis=Mock(
                ssl=Mock(
                    enabled=True,
                    check_expiry=True,
                    check_chain=True,
                    check_revocation=False,
                    warning_days=30,
                ),
                fingerprint=Mock(
                    enabled=True,
                    check_headers=True,
                    check_html=True,
                    check_scripts=True,
                    check_cookies=True,
                    check_dns=True,
                ),
                cve=Mock(enabled=True, cache_ttl=3600),
                headers=Mock(enabled=True, required_headers=[]),
            ),
        )
        service = AnalyzeService()
        assert service._proxy_rotator is None

    def test_resolve_proxy_prefers_explicit(self, analyze_service: AnalyzeService):
        """Explicit proxy takes priority over rotator."""
        from ciberwebscan.core.client.proxy import ProxyRotator

        analyze_service._proxy_rotator = ProxyRotator(proxies=["http://rotated:8080"])
        result = analyze_service._resolve_proxy("http://explicit:3128")
        assert result == "http://explicit:3128"

    def test_resolve_proxy_uses_rotator(self, analyze_service: AnalyzeService):
        """Rotator is used when no explicit proxy provided."""
        from ciberwebscan.core.client.proxy import ProxyRotator

        analyze_service._proxy_rotator = ProxyRotator(
            proxies=["http://p1:8080", "http://p2:8080"]
        )
        result = analyze_service._resolve_proxy(None)
        assert result == "http://p1:8080"

    def test_resolve_proxy_returns_none_without_rotator(
        self, analyze_service: AnalyzeService
    ):
        """Returns None when no explicit proxy and no rotator."""
        analyze_service._proxy_rotator = None
        result = analyze_service._resolve_proxy(None)
        assert result is None

    @patch("ciberwebscan.core.client.http_client.HTTPClient")
    @patch("ciberwebscan.services.analyze_service.get_config")
    def test_fingerprint_passes_resolved_proxy_to_http_client(
        self,
        mock_get_config: Mock,
        mock_http_client: Mock,
    ):
        """HTTPClient receives the proxy returned by _resolve_proxy."""
        http_config = Mock(
            timeout=Mock(read=30.0, connect=10.0),
            proxy=Mock(
                rotate=True,
                proxy_list=["http://p1:8080", "http://p2:8080"],
                rotation_interval=1,
            ),
        )
        mock_get_config.return_value = Mock(
            http=http_config,
            user_agent=Mock(mode="static", custom="TestAgent"),
            analysis=Mock(
                ssl=Mock(
                    enabled=True,
                    check_expiry=True,
                    check_chain=True,
                    check_revocation=False,
                    warning_days=30,
                ),
                fingerprint=Mock(
                    enabled=True,
                    check_headers=True,
                    check_html=True,
                    check_scripts=True,
                    check_cookies=True,
                    check_dns=True,
                ),
                cve=Mock(enabled=True, cache_ttl=3600),
                headers=Mock(enabled=True, required_headers=[]),
            ),
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

        assert mock_http_client.call_args.kwargs["proxy"] == "http://p1:8080"
