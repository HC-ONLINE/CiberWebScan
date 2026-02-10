"""
Tests for attack modules base functionality.
"""

from unittest.mock import Mock

import pytest

from ciberwebscan.core.attacks.base import (
    AttackConfig,
    AttackContext,
    AttackEngine,
    AttackIntensity,
)
from ciberwebscan.core.client import HTTPClient
from ciberwebscan.export.models import (
    AttackPayload,
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)


# Mock implementation of abstract AttackEngine
class MockAttackEngine(AttackEngine):
    """Mock attack engine for testing."""

    def __init__(self):
        super().__init__("mock_attack")

    async def execute(self, context):
        return []

    def get_payloads(self, intensity, max_count):
        return ["test_payload_1", "test_payload_2"]


@pytest.fixture
def attack_config():
    """Basic attack configuration."""
    return AttackConfig(
        target_url="https://example.com",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=10,
        timeout=5.0,
        user_consent=True,
    )


@pytest.fixture
def http_client_mock():
    """Mocked HTTP client."""
    client = Mock(spec=HTTPClient)
    client.get = Mock()
    client.post = Mock()
    client.request = Mock()
    return client


@pytest.fixture
def attack_context(attack_config, http_client_mock):
    """Attack context with mocked dependencies."""
    return AttackContext(config=attack_config, http_client=http_client_mock)


@pytest.fixture
def mock_response():
    """Mock HTTP response."""
    response = Mock()
    response.url = "https://example.com"
    response.status_code = 200
    response.text = "<html><body>Test page</body></html>"
    response.content = b"<html><body>Test page</body></html>"
    response.headers = {"Content-Type": "text/html"}
    return response


class TestAttackConfig:
    """Test AttackConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = AttackConfig(target_url="https://test.com")

        assert config.target_url == "https://test.com"
        assert config.intensity == AttackIntensity.MEDIUM
        assert config.max_payloads == 50
        assert config.timeout == 10.0
        assert config.delay_between_requests == 0.1
        assert config.user_consent is False
        assert config.verbose is False

    def test_custom_values(self):
        """Test custom configuration values."""
        config = AttackConfig(
            target_url="https://custom.com",
            intensity=AttackIntensity.HIGH,
            max_payloads=100,
            timeout=30.0,
            user_consent=True,
            verbose=True,
        )

        assert config.target_url == "https://custom.com"
        assert config.intensity == AttackIntensity.HIGH
        assert config.max_payloads == 100
        assert config.timeout == 30.0
        assert config.user_consent is True
        assert config.verbose is True


class TestAttackContext:
    """Test AttackContext functionality."""

    def test_initialization(self, attack_context):
        """Test context initialization."""
        assert attack_context.total_requests == 0
        assert attack_context.successful_requests == 0
        assert attack_context.failed_requests == 0
        assert len(attack_context.vulnerabilities) == 0

    def test_log_successful_request(self, attack_context):
        """Test logging successful requests."""
        attack_context.log_request(True)

        assert attack_context.total_requests == 1
        assert attack_context.successful_requests == 1
        assert attack_context.failed_requests == 0

    def test_log_failed_request(self, attack_context):
        """Test logging failed requests."""
        attack_context.log_request(False)

        assert attack_context.total_requests == 1
        assert attack_context.successful_requests == 0
        assert attack_context.failed_requests == 1

    def test_add_vulnerability(self, attack_context):
        """Test adding vulnerabilities."""
        vuln = VulnerabilityFinding(
            type="test",
            title="Test Vulnerability",
            description="Test description",
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            url="https://example.com",
            payload=AttackPayload(type="test", payload="test_payload"),
        )

        attack_context.add_vulnerability(vuln)

        assert len(attack_context.vulnerabilities) == 1
        assert attack_context.vulnerabilities[0] == vuln

    def test_elapsed_time(self, attack_context):
        """Test elapsed time calculation."""
        import time

        time.sleep(0.01)  # Small delay
        elapsed = attack_context.elapsed_time()
        assert elapsed > 0
        assert elapsed < 1.0  # Should be very small


class TestMockAttackEngine:
    """Test MockAttackEngine implementation."""

    def test_initialization(self):
        """Test engine initialization."""
        engine = MockAttackEngine()
        assert engine.name == "mock_attack"
        assert hasattr(engine.logger, "info")

    def test_validate_target(self):
        """Test target validation."""
        engine = MockAttackEngine()

        assert engine.validate_target("https://example.com") is True
        assert engine.validate_target("http://example.com") is True
        assert engine.validate_target("ftp://example.com") is False
        assert engine.validate_target("invalid-url") is False

    def test_create_payload_object(self):
        """Test payload object creation."""
        engine = MockAttackEngine()

        payload = engine.create_payload_object(
            payload_str="<script>alert(1)</script>",
            parameter="input_field",
            method="POST",
        )

        assert payload.type == "mock_attack"
        assert payload.payload == "<script>alert(1)</script>"
        assert payload.parameter == "input_field"
        assert payload.method == "POST"

    def test_create_vulnerability(self):
        """Test vulnerability creation."""
        engine = MockAttackEngine()

        payload = AttackPayload(
            type="test", payload="test_payload", parameter="test_param", method="GET"
        )

        vuln = engine.create_vulnerability(
            title="Test XSS",
            description="XSS vulnerability found",
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            url="https://example.com",
            payload=payload,
            evidence="Payload reflected in response",
            remediation="Sanitize user input",
            cwe_id="CWE-79",
            owasp_category="A03:2021",
        )

        assert vuln.type == "mock_attack"
        assert vuln.title == "Test XSS"
        assert vuln.severity == Severity.HIGH
        assert vuln.confidence == ConfidenceLevel.MEDIUM
        assert vuln.cwe_id == "CWE-79"

    @pytest.mark.asyncio
    async def test_send_request_get(self, attack_context, mock_response):
        """Test GET request sending."""
        engine = MockAttackEngine()
        # Configure the mock to return the mock_response directly
        attack_context.http_client.get = Mock(return_value=mock_response)

        response = await engine.send_request(
            attack_context, "https://example.com", "GET", params={"test": "value"}
        )

        assert response == mock_response
        assert attack_context.total_requests == 1
        assert attack_context.successful_requests == 1
        attack_context.http_client.get.assert_called_once_with(
            "https://example.com", params={"test": "value"}
        )

    @pytest.mark.asyncio
    async def test_send_request_post(self, attack_context, mock_response):
        """Test POST request sending."""
        engine = MockAttackEngine()
        # Configure the mock to return the mock_response directly
        attack_context.http_client.post = Mock(return_value=mock_response)

        response = await engine.send_request(
            attack_context, "https://example.com", "POST", data={"field": "value"}
        )

        assert response == mock_response
        attack_context.http_client.post.assert_called_once_with(
            "https://example.com", data={"field": "value"}, params={}
        )

    @pytest.mark.asyncio
    async def test_send_request_failure(self, attack_context):
        """Test request failure handling."""
        engine = MockAttackEngine()
        # Configure the mock to raise an exception
        attack_context.http_client.get = Mock(
            side_effect=Exception("Connection failed")
        )

        response = await engine.send_request(
            attack_context, "https://example.com", "GET"
        )

        assert response is None
        assert attack_context.total_requests == 1
        assert attack_context.failed_requests == 1

    def test_extract_forms(self):
        """Test form extraction from HTML."""
        engine = MockAttackEngine()

        html = """
        <html>
            <body>
                <form action="/login" method="POST">
                    <input type="text" name="username" value="">
                    <input type="password" name="password" value="">
                    <input type="submit" value="Login">
                </form>
                <form action="/search" method="GET">
                    <input type="text" name="q" value="">
                </form>
            </body>
        </html>
        """

        forms = engine.extract_forms(html)

        assert len(forms) == 2

        # First form
        assert forms[0]["action"] == "/login"
        assert forms[0]["method"] == "POST"
        assert len(forms[0]["inputs"]) == 3

        # Check input fields
        usernames = [inp for inp in forms[0]["inputs"] if inp["name"] == "username"]
        assert len(usernames) == 1
        assert usernames[0]["type"] == "text"

        # Second form
        assert forms[1]["action"] == "/search"
        assert forms[1]["method"] == "GET"

    def test_extract_forms_invalid_html(self):
        """Test form extraction with invalid HTML."""
        engine = MockAttackEngine()

        # Should not crash on invalid HTML
        forms = engine.extract_forms("<invalid>html")
        assert isinstance(forms, list)

    def test_should_test_parameter(self):
        """Test parameter filtering logic."""
        engine = MockAttackEngine()

        # Should test normal parameters
        assert engine.should_test_parameter("username") is True
        assert engine.should_test_parameter("search_query") is True
        assert engine.should_test_parameter("file_path") is True

        # Should skip security tokens
        assert engine.should_test_parameter("csrf_token") is False
        assert engine.should_test_parameter("authenticity_token") is False
        assert engine.should_test_parameter("_token") is False
        assert engine.should_test_parameter("sessionid") is False
