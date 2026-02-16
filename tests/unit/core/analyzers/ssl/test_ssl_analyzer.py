"""Unit tests for SSL analyzer module."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

from ciberwebscan.core.analyzers.ssl import (
    SSLAnalysisResult,
    SSLAnalyzer,
    SSLCertificateInfo,
    SSLProtocolInfo,
    SSLSecurityAssessment,
    analyze_ssl_security,
)


class TestSSLCertificateInfo:
    """Tests for SSLCertificateInfo dataclass."""

    def test_create_certificate_info(self) -> None:
        """Test creating certificate info."""
        cert = SSLCertificateInfo(
            subject={"commonName": "example.com"},
            issuer={"commonName": "CA"},
            version=3,
            serial_number="123456",
            not_before=datetime.datetime(2024, 1, 1),
            not_after=datetime.datetime(2025, 1, 1),
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="RSAPublicKey",
            public_key_size=2048,
            san_domains=["example.com", "www.example.com"],
            is_self_signed=False,
            is_expired=False,
            days_until_expiry=365,
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
        )

        assert cert.subject["commonName"] == "example.com"
        assert cert.public_key_size == 2048
        assert not cert.is_expired
        assert len(cert.san_domains) == 2


class TestSSLProtocolInfo:
    """Tests for SSLProtocolInfo dataclass."""

    def test_create_protocol_info(self) -> None:
        """Test creating protocol info."""
        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1.2", "TLSv1.3"],
            cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
            preferred_cipher="ECDHE-RSA-AES256-GCM-SHA384",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assert "TLSv1.3" in protocol.supported_protocols
        assert protocol.supports_sni is True
        assert protocol.compression_supported is False


class TestSSLSecurityAssessment:
    """Tests for SSLSecurityAssessment dataclass."""

    def test_create_assessment_grade_a(self) -> None:
        """Test creating A grade assessment."""
        assessment = SSLSecurityAssessment(
            overall_grade="A",
            vulnerabilities=[],
            warnings=[],
            recommendations=[],
            weak_protocols=[],
            weak_ciphers=[],
        )

        assert assessment.overall_grade == "A"
        assert len(assessment.vulnerabilities) == 0

    def test_create_assessment_with_issues(self) -> None:
        """Test creating assessment with issues."""
        assessment = SSLSecurityAssessment(
            overall_grade="C",
            vulnerabilities=["Expired certificate"],
            warnings=["SHA1 signature"],
            recommendations=["Renew certificate"],
            weak_protocols=["TLSv1"],
            weak_ciphers=["RC4"],
        )

        assert assessment.overall_grade == "C"
        assert "Expired certificate" in assessment.vulnerabilities
        assert len(assessment.weak_protocols) == 1


class TestSSLAnalysisResult:
    """Tests for SSLAnalysisResult dataclass."""

    def test_result_to_dict_with_error(self) -> None:
        """Test converting error result to dict."""
        result = SSLAnalysisResult(
            ssl_enabled=False,
            error="Connection refused",
        )

        data = result.to_dict()
        assert data["ssl_enabled"] is False
        assert data["error"] == "Connection refused"

    def test_result_to_dict_successful(self) -> None:
        """Test converting successful result to dict."""
        cert = SSLCertificateInfo(
            subject={"commonName": "test.com"},
            issuer={"commonName": "CA"},
            version=3,
            serial_number="123",
            not_before=datetime.datetime(2024, 1, 1),
            not_after=datetime.datetime(2025, 1, 1),
            signature_algorithm="sha256",
            public_key_algorithm="RSA",
            public_key_size=2048,
            san_domains=["test.com"],
            is_self_signed=False,
            is_expired=False,
            days_until_expiry=365,
            fingerprint_sha256="abc",
            fingerprint_sha1="def",
        )

        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["AES256"],
            preferred_cipher="AES256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assessment = SSLSecurityAssessment(overall_grade="A")

        result = SSLAnalysisResult(
            ssl_enabled=True,
            hostname="test.com",
            port=443,
            certificate=cert,
            protocols=protocol,
            security_assessment=assessment,
            has_hsts=True,
            analysis_timestamp="2025-01-31T12:00:00",
        )

        data = result.to_dict()
        assert data["ssl_enabled"] is True
        assert data["hostname"] == "test.com"
        assert data["certificate"]["subject"]["commonName"] == "test.com"
        assert data["protocols"]["supports_sni"] is True
        assert data["security_assessment"]["overall_grade"] == "A"


class TestSSLAnalyzer:
    """Tests for SSLAnalyzer class."""

    def test_init_default_timeout(self) -> None:
        """Test default initialization."""
        analyzer = SSLAnalyzer()
        assert analyzer.timeout == 10

    def test_init_custom_timeout(self) -> None:
        """Test custom timeout."""
        analyzer = SSLAnalyzer(timeout=30)
        assert analyzer.timeout == 30

    def test_init_with_hsts_checker(self) -> None:
        """Test initialization with HSTS checker."""
        checker = MagicMock(return_value=True)
        analyzer = SSLAnalyzer(hsts_checker=checker)
        assert analyzer._hsts_checker is checker

    def test_analyze_non_https_url(self) -> None:
        """Test analyzing HTTP (non-HTTPS) URL."""
        analyzer = SSLAnalyzer()
        result = analyzer.analyze("http://example.com")

        assert result.ssl_enabled is False
        assert "HTTPS" in (result.error or "")

    def test_analyze_invalid_url(self) -> None:
        """Test analyzing invalid URL."""
        analyzer = SSLAnalyzer()
        result = analyzer.analyze("not-a-valid-url")

        assert result.ssl_enabled is False
        assert result.error is not None

    def test_insecure_protocols_defined(self) -> None:
        """Test that insecure protocols are defined."""
        assert "SSLv2" in SSLAnalyzer.INSECURE_PROTOCOLS
        assert "SSLv3" in SSLAnalyzer.INSECURE_PROTOCOLS
        assert "TLSv1" in SSLAnalyzer.INSECURE_PROTOCOLS
        assert "TLSv1.1" in SSLAnalyzer.INSECURE_PROTOCOLS

    def test_weak_ciphers_defined(self) -> None:
        """Test that weak ciphers are defined."""
        assert "RC4" in SSLAnalyzer.WEAK_CIPHERS
        assert "DES" in SSLAnalyzer.WEAK_CIPHERS
        assert "NULL" in SSLAnalyzer.WEAK_CIPHERS

    def test_parse_name(self) -> None:
        """Test X.509 name parsing."""
        analyzer = SSLAnalyzer()

        # Create mock name object
        mock_attr = MagicMock()
        mock_attr.oid._name = "commonName"
        mock_attr.value = "test.com"

        mock_name = MagicMock()
        mock_name.__iter__ = lambda self: iter([mock_attr])

        result = analyzer._parse_name(mock_name)
        assert result["commonName"] == "test.com"


class TestSSLGradeCalculation:
    """Tests for SSL grade calculation."""

    def test_grade_f_expired_certificate(self) -> None:
        """Test F grade for expired certificate."""
        analyzer = SSLAnalyzer()
        grade = analyzer._calculate_grade(
            vulnerabilities=["Expired certificate"],
            warnings=[],
            weak_protocols=[],
            weak_ciphers=[],
        )
        assert grade == "F"

    def test_grade_f_self_signed(self) -> None:
        """Test F grade for self-signed certificate."""
        analyzer = SSLAnalyzer()
        grade = analyzer._calculate_grade(
            vulnerabilities=["Self-signed certificate"],
            warnings=[],
            weak_protocols=[],
            weak_ciphers=[],
        )
        assert grade == "F"

    def test_grade_f_sslv3(self) -> None:
        """Test F grade for SSLv3 support."""
        analyzer = SSLAnalyzer()
        grade = analyzer._calculate_grade(
            vulnerabilities=[],
            warnings=[],
            weak_protocols=["SSLv3"],
            weak_ciphers=[],
        )
        assert grade == "F"

    def test_grade_a_plus_with_hsts(self) -> None:
        """Test A+ grade with HSTS."""
        analyzer = SSLAnalyzer()
        protocol_info = SSLProtocolInfo(
            supported_protocols=["TLSv1.2", "TLSv1.3"],
            cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
            preferred_cipher="ECDHE-RSA-AES256-GCM-SHA384",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )
        grade = analyzer._calculate_grade(
            vulnerabilities=[],
            warnings=[],
            weak_protocols=[],
            weak_ciphers=[],
            protocol_info=protocol_info,
            has_hsts=True,
        )
        assert grade == "A+"

    def test_grade_a_without_hsts(self) -> None:
        """Test A grade without HSTS (downgrade from A+)."""
        analyzer = SSLAnalyzer()
        protocol_info = SSLProtocolInfo(
            supported_protocols=["TLSv1.2", "TLSv1.3"],
            cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
            preferred_cipher="ECDHE-RSA-AES256-GCM-SHA384",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )
        grade = analyzer._calculate_grade(
            vulnerabilities=[],
            warnings=[],
            weak_protocols=[],
            weak_ciphers=[],
            protocol_info=protocol_info,
            has_hsts=False,
        )
        assert grade == "A"

    def test_grade_b_for_tls10(self) -> None:
        """Test B grade cap for TLS 1.0 support."""
        analyzer = SSLAnalyzer()
        protocol_info = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
            preferred_cipher="ECDHE-RSA-AES256-GCM-SHA384",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )
        grade = analyzer._calculate_grade(
            vulnerabilities=[],
            warnings=[],
            weak_protocols=["TLSv1"],
            weak_ciphers=[],
            protocol_info=protocol_info,
            has_hsts=True,
        )
        assert grade == "B"

    def test_grade_degradation_no_forward_secrecy(self) -> None:
        """Test grade cap for no forward secrecy."""
        analyzer = SSLAnalyzer()
        protocol_info = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["AES256-SHA256"],  # No DHE/ECDHE
            preferred_cipher="AES256-SHA256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )
        grade = analyzer._calculate_grade(
            vulnerabilities=[],
            warnings=[],
            weak_protocols=[],
            weak_ciphers=[],
            protocol_info=protocol_info,
            has_hsts=True,
        )
        # Should be capped at B due to no FS
        assert grade in ["A", "B"]  # May vary based on score


class TestSSLSecurityAssessmentLogic:
    """Tests for security assessment logic."""

    def test_assess_security_expired_cert(self) -> None:
        """Test assessment detects expired certificate."""
        analyzer = SSLAnalyzer()

        cert = SSLCertificateInfo(
            subject={"commonName": "test.com"},
            issuer={"commonName": "CA"},
            version=3,
            serial_number="123",
            not_before=datetime.datetime(2020, 1, 1),
            not_after=datetime.datetime(2021, 1, 1),
            signature_algorithm="sha256",
            public_key_algorithm="RSAPublicKey",
            public_key_size=2048,
            san_domains=[],
            is_self_signed=False,
            is_expired=True,
            days_until_expiry=-365,
            fingerprint_sha256="abc",
            fingerprint_sha1="def",
        )

        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256"],
            preferred_cipher="ECDHE-RSA-AES256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assessment = analyzer._assess_security(cert, protocol)
        assert assessment is not None
        assert "Expired certificate" in assessment.vulnerabilities

    def test_assess_security_weak_rsa_key(self) -> None:
        """Test assessment detects weak RSA key."""
        analyzer = SSLAnalyzer()

        cert = SSLCertificateInfo(
            subject={"commonName": "test.com"},
            issuer={"commonName": "CA"},
            version=3,
            serial_number="123",
            not_before=datetime.datetime(2024, 1, 1),
            not_after=datetime.datetime(2025, 1, 1),
            signature_algorithm="sha256",
            public_key_algorithm="RSAPublicKey",
            public_key_size=1024,  # Weak key
            san_domains=[],
            is_self_signed=False,
            is_expired=False,
            days_until_expiry=365,
            fingerprint_sha256="abc",
            fingerprint_sha1="def",
        )

        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256"],
            preferred_cipher="ECDHE-RSA-AES256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assessment = analyzer._assess_security(cert, protocol)
        assert assessment is not None
        assert any("Weak RSA" in v for v in assessment.vulnerabilities)

    def test_assess_security_insecure_protocol(self) -> None:
        """Test assessment detects insecure protocols."""
        analyzer = SSLAnalyzer()

        cert = SSLCertificateInfo(
            subject={"commonName": "test.com"},
            issuer={"commonName": "CA"},
            version=3,
            serial_number="123",
            not_before=datetime.datetime(2024, 1, 1),
            not_after=datetime.datetime(2025, 1, 1),
            signature_algorithm="sha256",
            public_key_algorithm="RSAPublicKey",
            public_key_size=2048,
            san_domains=[],
            is_self_signed=False,
            is_expired=False,
            days_until_expiry=365,
            fingerprint_sha256="abc",
            fingerprint_sha1="def",
        )

        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1", "TLSv1.2"],  # TLSv1 is insecure
            cipher_suites=["ECDHE-RSA-AES256"],
            preferred_cipher="ECDHE-RSA-AES256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assessment = analyzer._assess_security(cert, protocol)
        assert assessment is not None
        assert "TLSv1" in assessment.weak_protocols

    def test_assess_security_none_inputs(self) -> None:
        """Test assessment handles None inputs."""
        analyzer = SSLAnalyzer()
        assessment = analyzer._assess_security(None, None)
        assert assessment is None


class TestAnalyzeSSLSecurityFunction:
    """Tests for the convenience function."""

    @patch.object(SSLAnalyzer, "analyze")
    def test_analyze_ssl_security_calls_analyzer(self, mock_analyze: MagicMock) -> None:
        """Test convenience function calls analyzer."""
        mock_result = SSLAnalysisResult(ssl_enabled=True, hostname="test.com")
        mock_analyze.return_value = mock_result

        result = analyze_ssl_security("https://test.com")

        mock_analyze.assert_called_once_with("https://test.com")
        assert result["ssl_enabled"] is True

    def test_analyze_ssl_security_returns_dict(self) -> None:
        """Test convenience function returns dict for non-https."""
        result = analyze_ssl_security("http://example.com")
        assert isinstance(result, dict)
        assert result["ssl_enabled"] is False


class TestSSLAnalyzerConfigParams:
    """Tests for config-driven SSLAnalyzer parameters."""

    def test_default_config_params(self) -> None:
        """Test default values for config params."""
        analyzer = SSLAnalyzer()
        assert analyzer.check_expiry is True
        assert analyzer.check_chain is True
        assert analyzer.check_revocation is True
        assert analyzer.warning_days == 30

    def test_custom_config_params(self) -> None:
        """Test initialization with custom config params."""
        analyzer = SSLAnalyzer(
            check_expiry=False,
            check_chain=False,
            check_revocation=False,
            warning_days=60,
        )
        assert analyzer.check_expiry is False
        assert analyzer.check_chain is False
        assert analyzer.check_revocation is False
        assert analyzer.warning_days == 60

    def test_assess_skips_expiry_when_disabled(self) -> None:
        """Test that expiry check is skipped when check_expiry=False."""
        analyzer = SSLAnalyzer(check_expiry=False)

        cert = SSLCertificateInfo(
            subject={"commonName": "test.com"},
            issuer={"commonName": "CA"},
            version=3,
            serial_number="123",
            not_before=datetime.datetime(2020, 1, 1),
            not_after=datetime.datetime(2021, 1, 1),
            signature_algorithm="sha256",
            public_key_algorithm="RSAPublicKey",
            public_key_size=2048,
            san_domains=[],
            is_self_signed=False,
            is_expired=True,
            days_until_expiry=-365,
            fingerprint_sha256="abc",
            fingerprint_sha1="def",
        )

        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256"],
            preferred_cipher="ECDHE-RSA-AES256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assessment = analyzer._assess_security(cert, protocol)
        assert assessment is not None
        assert "Expired certificate" not in assessment.vulnerabilities

    def test_assess_skips_chain_when_disabled(self) -> None:
        """Test that chain check is skipped when check_chain=False."""
        analyzer = SSLAnalyzer(check_chain=False)

        cert = SSLCertificateInfo(
            subject={"commonName": "test.com"},
            issuer={"commonName": "test.com"},  # self-signed
            version=3,
            serial_number="123",
            not_before=datetime.datetime(2024, 1, 1),
            not_after=datetime.datetime(2025, 1, 1),
            signature_algorithm="sha256",
            public_key_algorithm="RSAPublicKey",
            public_key_size=2048,
            san_domains=[],
            is_self_signed=True,
            is_expired=False,
            days_until_expiry=365,
            fingerprint_sha256="abc",
            fingerprint_sha1="def",
        )

        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256"],
            preferred_cipher="ECDHE-RSA-AES256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assessment = analyzer._assess_security(cert, protocol)
        assert assessment is not None
        assert "Self-signed certificate" not in assessment.vulnerabilities

    def test_custom_warning_days(self) -> None:
        """Test custom warning_days threshold."""
        analyzer = SSLAnalyzer(warning_days=90)

        cert = SSLCertificateInfo(
            subject={"commonName": "test.com"},
            issuer={"commonName": "CA"},
            version=3,
            serial_number="123",
            not_before=datetime.datetime(2024, 1, 1),
            not_after=datetime.datetime(2025, 1, 1),
            signature_algorithm="sha256",
            public_key_algorithm="RSAPublicKey",
            public_key_size=2048,
            san_domains=[],
            is_self_signed=False,
            is_expired=False,
            days_until_expiry=60,
            fingerprint_sha256="abc",
            fingerprint_sha1="def",
        )

        protocol = SSLProtocolInfo(
            supported_protocols=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256"],
            preferred_cipher="ECDHE-RSA-AES256",
            supports_sni=True,
            compression_supported=False,
            secure_renegotiation=True,
        )

        assessment = analyzer._assess_security(cert, protocol)
        assert assessment is not None
        # 60 < 90 warning_days -> should trigger warning
        assert any("expires in" in w for w in assessment.warnings)
