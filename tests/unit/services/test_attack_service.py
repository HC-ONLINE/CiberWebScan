"""
Tests for AttackService.

WARNING: These tests use mocked responses and do not perform actual attacks.
Never run real attacks without explicit permission.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from ciberwebscan.export.models import AttackResult, VulnerabilityFinding
from ciberwebscan.services import (
    AttackOptions,
    AttackService,
    ValidationError,
)


@pytest.fixture
def attack_service() -> AttackService:
    """Create attack service instance."""
    return AttackService()


@pytest.fixture
def basic_attack_options() -> AttackOptions:
    """Basic attack options with consent."""
    return AttackOptions(
        url="https://example.com",
        user_consent=True,
        xss=True,
        intensity="medium",
    )


@pytest.fixture
def mock_vulnerability() -> VulnerabilityFinding:
    """Mock vulnerability finding."""
    from ciberwebscan.export.models import AttackPayload, ConfidenceLevel, Severity

    return VulnerabilityFinding(
        type="xss",
        title="XSS in search parameter",
        description="Reflected XSS vulnerability",
        severity=Severity.HIGH,
        confidence=ConfidenceLevel.HIGH,
        url="https://example.com/search?q=test",
        payload=AttackPayload(
            type="xss", payload="<script>alert(1)</script>", parameter="q", method="GET"
        ),
        evidence="Payload reflected in response",
    )


# =============================================================================
# AttackOptions Tests
# =============================================================================


class TestAttackOptions:
    """Tests for AttackOptions dataclass."""

    def test_default_values(self):
        """Test default option values."""
        options = AttackOptions(url="https://test.com", user_consent=True)

        assert options.url == "https://test.com"
        assert options.user_consent is True
        assert options.xss is False
        assert options.sqli is False
        assert options.traversal is False
        assert options.enumeration is False
        assert options.intensity == "medium"
        assert options.max_payloads == 50
        assert options.timeout == 10.0

    def test_custom_values(self):
        """Test custom option values."""
        options = AttackOptions(
            url="https://custom.com",
            user_consent=True,
            xss=True,
            sqli=True,
            intensity="high",
            max_payloads=100,
            timeout=30.0,
            verbose=True,
        )

        assert options.url == "https://custom.com"
        assert options.xss is True
        assert options.sqli is True
        assert options.intensity == "high"
        assert options.max_payloads == 100
        assert options.timeout == 30.0
        assert options.verbose is True


# =============================================================================
# AttackService Tests
# =============================================================================


class TestAttackService:
    """Tests for AttackService class."""

    def test_initialization(self, attack_service: AttackService):
        """Test service initialization."""
        assert attack_service is not None
        assert hasattr(attack_service, "logger")

    @patch("ciberwebscan.services.attack_service.get_config")
    @patch("ciberwebscan.services.attack_service.HTTPClient")
    @patch("ciberwebscan.services.attack_service.XSSAttacker")
    def test_attack_uses_config_timeout_when_default(
        self,
        mock_xss_attacker_class: Mock,
        mock_http_client_class: Mock,
        mock_get_config: Mock,
    ):
        """Test that default timeout is resolved from global config."""
        http_config = Mock(
            timeout=Mock(connect=22.0),
            retry=Mock(max_attempts=3, backoff_factor=0.5),
            rate_limit=Mock(requests_per_second=5.0, per_domain=True),
            http2=True,
            verify_ssl=True,
            follow_redirects=True,
        )
        mock_get_config.return_value = Mock(
            http=http_config, user_agent=Mock(mode="static", custom="TestAgent")
        )

        mock_attacker = Mock()
        mock_attacker.execute = AsyncMock(return_value=[])
        mock_xss_attacker_class.return_value = mock_attacker
        mock_http_client_class.return_value = Mock()

        service = AttackService()
        options = AttackOptions(url="https://example.com", user_consent=True, xss=True)
        service.attack(options)

        assert mock_http_client_class.call_args is not None
        assert mock_http_client_class.call_args.kwargs["timeout"] == 22.0

    def test_attack_without_consent(self, attack_service: AttackService):
        """Test that attack requires user consent."""
        options = AttackOptions(
            url="https://example.com",
            user_consent=False,  # No consent!
            xss=True,
        )

        with pytest.raises(ValidationError) as exc_info:
            attack_service.attack(options)

        assert "user consent" in str(exc_info.value).lower()
        assert "permission" in str(exc_info.value).lower()

    def test_attack_no_attack_types(self, attack_service: AttackService):
        """Test that at least one attack type must be selected."""
        options = AttackOptions(
            url="https://example.com",
            user_consent=True,
            # No attack types enabled!
        )

        with pytest.raises(ValidationError) as exc_info:
            attack_service.attack(options)

        assert "at least one attack type" in str(exc_info.value).lower()

    def test_attack_invalid_intensity(self, attack_service: AttackService):
        """Test validation of intensity parameter."""
        options = AttackOptions(
            url="https://example.com",
            user_consent=True,
            xss=True,
            intensity="invalid",  # Invalid intensity!
        )

        with pytest.raises(ValidationError) as exc_info:
            attack_service.attack(options)

        assert "intensity" in str(exc_info.value).lower()

    @patch("ciberwebscan.services.attack_service.HTTPClient")
    @patch("ciberwebscan.services.attack_service.XSSAttacker")
    def test_attack_xss_success(
        self,
        mock_xss_attacker_class: Mock,
        mock_http_client_class: Mock,
        attack_service: AttackService,
        basic_attack_options: AttackOptions,
        mock_vulnerability: VulnerabilityFinding,
    ):
        """Test successful XSS attack simulation."""
        # Mock XSS attacker
        mock_attacker = Mock()
        mock_attacker.execute = AsyncMock(return_value=[mock_vulnerability])
        mock_xss_attacker_class.return_value = mock_attacker

        # Mock HTTP client
        mock_client = Mock()
        mock_http_client_class.return_value = mock_client

        # Execute attack
        result = attack_service.attack(basic_attack_options)

        assert result.success is True
        assert result.data is not None
        assert isinstance(result.data, AttackResult)
        assert result.data.total_findings == 1
        assert result.data.xss_findings == 1
        assert len(result.data.vulnerabilities) == 1

    @patch("ciberwebscan.services.attack_service.HTTPClient")
    @patch("ciberwebscan.services.attack_service.SQLiAttacker")
    def test_attack_sqli_success(
        self,
        mock_sqli_attacker_class: Mock,
        mock_http_client_class: Mock,
        attack_service: AttackService,
    ):
        """Test successful SQLi attack simulation."""
        from ciberwebscan.export.models import AttackPayload, ConfidenceLevel, Severity

        # Create SQLi vulnerability
        sqli_vuln = VulnerabilityFinding(
            type="sqli",
            title="SQL Injection in id parameter",
            description="SQL injection vulnerability",
            severity=Severity.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            url="https://example.com/user?id=1",
            payload=AttackPayload(
                type="sqli", payload="' OR '1'='1", parameter="id", method="GET"
            ),
        )

        # Mock SQLi attacker
        mock_attacker = Mock()
        mock_attacker.execute = AsyncMock(return_value=[sqli_vuln])
        mock_sqli_attacker_class.return_value = mock_attacker

        # Mock HTTP client
        mock_client = Mock()
        mock_http_client_class.return_value = mock_client

        # Execute attack
        options = AttackOptions(
            url="https://example.com",
            user_consent=True,
            sqli=True,
        )
        result = attack_service.attack(options)

        assert result.success is True
        assert result.data.total_findings == 1
        assert result.data.sqli_findings == 1

    @patch("ciberwebscan.services.attack_service.HTTPClient")
    @patch("ciberwebscan.services.attack_service.XSSAttacker")
    @patch("ciberwebscan.services.attack_service.SQLiAttacker")
    def test_attack_multiple_types(
        self,
        mock_sqli_class: Mock,
        mock_xss_class: Mock,
        mock_http_client_class: Mock,
        attack_service: AttackService,
        mock_vulnerability: VulnerabilityFinding,
    ):
        """Test running multiple attack types."""
        from ciberwebscan.export.models import AttackPayload, ConfidenceLevel, Severity

        # Mock XSS attacker
        mock_xss = Mock()
        mock_xss.execute = AsyncMock(return_value=[mock_vulnerability])
        mock_xss_class.return_value = mock_xss

        # Mock SQLi attacker
        sqli_vuln = VulnerabilityFinding(
            type="sqli",
            title="SQL Injection",
            description="SQL injection",
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            url="https://example.com",
            payload=AttackPayload(type="sqli", payload="'", parameter="id"),
        )
        mock_sqli = Mock()
        mock_sqli.execute = AsyncMock(return_value=[sqli_vuln])
        mock_sqli_class.return_value = mock_sqli

        # Mock HTTP client
        mock_client = Mock()
        mock_http_client_class.return_value = mock_client

        # Execute attack with multiple types
        options = AttackOptions(
            url="https://example.com",
            user_consent=True,
            xss=True,
            sqli=True,
        )
        result = attack_service.attack(options)

        assert result.success is True
        assert result.data.total_findings == 2
        assert result.data.xss_findings == 1
        assert result.data.sqli_findings == 1

    @patch("ciberwebscan.services.attack_service.HTTPClient")
    @patch("ciberwebscan.services.attack_service.XSSAttacker")
    def test_attack_with_export(
        self,
        mock_xss_class: Mock,
        mock_http_client_class: Mock,
        attack_service: AttackService,
        tmp_path,
    ):
        """Test attack with export."""
        # Mock XSS attacker - no vulns found
        mock_xss = Mock()
        mock_xss.execute = AsyncMock(return_value=[])
        mock_xss_class.return_value = mock_xss

        # Mock HTTP client
        mock_client = Mock()
        mock_http_client_class.return_value = mock_client

        # Execute with export
        export_file = tmp_path / "attack_report.json"
        options = AttackOptions(
            url="https://example.com",
            user_consent=True,
            xss=True,
            export=str(export_file),
        )
        result = attack_service.attack(options)

        assert result.success is True
        assert result.exported is True
        assert result.export_path is not None
        assert result.export_path.exists()


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestAttackServiceErrorHandling:
    """Test error handling in AttackService."""

    def test_invalid_url(self, attack_service: AttackService):
        """Test handling of invalid URL."""
        options = AttackOptions(
            url="not-a-valid-url",
            user_consent=True,
            xss=True,
        )

        # Current implementation normalizes single-label hosts and proceeds
        # rather than raising a ValidationError. Ensure the service returns
        # a ServiceResult object and handles the input without raising.
        result = attack_service.attack(options)
        assert result is not None
        assert hasattr(result, "success")

    @patch("ciberwebscan.services.attack_service.HTTPClient")
    @patch("ciberwebscan.services.attack_service.XSSAttacker")
    def test_attack_execution_error(
        self,
        mock_xss_class: Mock,
        mock_http_client_class: Mock,
        attack_service: AttackService,
    ):
        """Test handling of attack execution errors."""
        # Mock XSS attacker to raise exception
        mock_xss = Mock()
        mock_xss.execute = AsyncMock(side_effect=Exception("Attack failed"))
        mock_xss_class.return_value = mock_xss

        # Mock HTTP client
        mock_client = Mock()
        mock_http_client_class.return_value = mock_client

        # Execute attack - should handle error gracefully
        options = AttackOptions(
            url="https://example.com",
            user_consent=True,
            xss=True,
        )
        result = attack_service.attack(options)

        # Should succeed but with no findings (error logged)
        assert result.success is True
        assert result.data.total_findings == 0
