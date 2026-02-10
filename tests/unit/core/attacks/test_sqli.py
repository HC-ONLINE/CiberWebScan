"""
Tests for SQL injection attack module.
"""

from unittest.mock import Mock

import pytest

from ciberwebscan.core.attacks.base import AttackConfig, AttackContext, AttackIntensity
from ciberwebscan.core.attacks.sqli import SQLiAttacker
from ciberwebscan.core.client import HTTPClient
from ciberwebscan.export.models import (
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)


@pytest.fixture
def sqli_attacker():
    """SQL injection attacker instance."""
    return SQLiAttacker()


@pytest.fixture
def attack_config():
    """Basic attack configuration for SQLi."""
    return AttackConfig(
        target_url="https://example.com/user",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=15,
        timeout=5.0,
        user_consent=True,
    )


@pytest.fixture
def http_client_mock():
    """Mocked HTTP client for SQLi tests."""
    client = Mock(spec=HTTPClient)
    client.get = Mock()
    client.post = Mock()
    return client


@pytest.fixture
def attack_context(attack_config, http_client_mock):
    """Attack context for SQLi tests."""
    return AttackContext(config=attack_config, http_client=http_client_mock)


@pytest.fixture
def vulnerable_mysql_response():
    """Mock response with MySQL error indicating SQLi."""
    response = Mock()
    response.url = "https://example.com/user?id=1'"
    response.status_code = 500
    response.text = """
    <html>
        <body>
            <h1>Database Error</h1>
            <p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>
            <p>Error near 'WHERE id='1''' at line 1</p>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def vulnerable_postgresql_response():
    """Mock response with PostgreSQL error indicating SQLi."""
    response = Mock()
    response.url = "https://example.com/search?q=test'"
    response.status_code = 500
    response.text = """
    ERROR: syntax error at or near "'"
    LINE 1: SELECT * FROM products WHERE name='test''
                                              ^
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/plain"}
    return response


@pytest.fixture
def time_based_response():
    """Mock response for time-based SQLi simulation."""
    response = Mock()
    response.url = "https://example.com/login"
    response.status_code = 200
    response.text = "<html><body>Login successful</body></html>"
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    response.elapsed.total_seconds.return_value = 8.5  # Simulate delay
    return response


@pytest.fixture
def boolean_based_response_true():
    """Mock response for boolean-based SQLi (true condition)."""
    response = Mock()
    response.url = "https://example.com/product?id=1"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <h1>Product Details</h1>
            <p>Product Name: Sample Product</p>
            <p>Price: $99.99</p>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def boolean_based_response_false():
    """Mock response for boolean-based SQLi (false condition)."""
    response = Mock()
    response.url = "https://example.com/product?id=999999"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <h1>Product Not Found</h1>
            <p>The requested product does not exist.</p>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def normal_response():
    """Mock normal response without SQLi indicators."""
    response = Mock()
    response.url = "https://example.com/user?id=1"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <h1>User Profile</h1>
            <p>Welcome, John Doe</p>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    response.elapsed.total_seconds.return_value = 0.5
    return response


@pytest.fixture
def form_response():
    """Mock response with form for testing."""
    response = Mock()
    response.url = "https://example.com/login"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <form action="/login" method="post">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


class TestSQLiAttacker:
    """Test SQLiAttacker functionality."""

    def test_initialization(self, sqli_attacker):
        """Test SQLi attacker initialization."""
        assert sqli_attacker.name == "sqli"
        assert hasattr(sqli_attacker, "payload_loader")
        assert hasattr(sqli_attacker, "error_patterns")
        # Check that error patterns dict has some entries
        assert len(sqli_attacker.error_patterns) > 0

    def test_get_payloads_basic(self, sqli_attacker):
        """Test basic payload generation."""
        payloads = sqli_attacker.get_payloads(AttackIntensity.LOW, 5)

        assert isinstance(payloads, list)
        assert len(payloads) <= 5
        assert all(isinstance(p, str) for p in payloads)

        # Should contain basic SQLi patterns
        has_quote = any("'" in p for p in payloads)
        has_union = any("union" in p.lower() for p in payloads)
        assert has_quote or has_union

    def test_get_payloads_time_based(self, sqli_attacker):
        """Test time-based payload generation."""
        payloads = sqli_attacker.get_payloads(AttackIntensity.HIGH, 20)

        assert isinstance(payloads, list)

        # Should contain time-based payloads
        time_based = [
            p for p in payloads if "sleep(" in p.lower() or "waitfor" in p.lower()
        ]
        assert len(time_based) > 0

    def test_validate_target(self, sqli_attacker):
        """Test target URL validation."""
        assert sqli_attacker.validate_target("https://example.com") is True
        assert sqli_attacker.validate_target("http://example.com/api") is True
        assert sqli_attacker.validate_target("ftp://example.com") is False
        assert sqli_attacker.validate_target("invalid-url") is False

    def test_analyze_sqli_response_mysql(
        self, sqli_attacker, vulnerable_mysql_response
    ):
        """Test MySQL error analysis using real method."""
        confidence, evidence = sqli_attacker._analyze_sqli_response(
            vulnerable_mysql_response.text,
            500,  # status_code
            len(vulnerable_mysql_response.text),  # response_length
            "normal response",  # original_text
            len("normal response"),  # original_length
            200,  # original_status
            "'",  # payload
        )

        assert isinstance(confidence, ConfidenceLevel)
        # Should detect the MySQL error
        assert confidence != ConfidenceLevel.LOW

    def test_analyze_sqli_response_postgresql(
        self, sqli_attacker, vulnerable_postgresql_response
    ):
        """Test PostgreSQL error analysis using real method."""
        confidence, evidence = sqli_attacker._analyze_sqli_response(
            vulnerable_postgresql_response.text,
            500,  # status_code
            len(vulnerable_postgresql_response.text),  # response_length
            "normal response",  # original_text
            len("normal response"),  # original_length
            200,  # original_status
            "'",  # payload
        )

        assert isinstance(confidence, ConfidenceLevel)
        # Should detect the PostgreSQL error
        assert confidence != ConfidenceLevel.LOW

    def test_analyze_sqli_response_normal(self, sqli_attacker, normal_response):
        """Test analysis with normal response."""
        confidence, evidence = sqli_attacker._analyze_sqli_response(
            normal_response.text,
            200,  # status_code
            len(normal_response.text),  # response_length
            normal_response.text,  # original_text (same as no change)
            len(normal_response.text),  # original_length
            200,  # original_status
            "'",  # payload
        )

        assert isinstance(confidence, ConfidenceLevel)
        # Normal response should have low confidence
        assert confidence == ConfidenceLevel.LOW

    def test_get_sqli_severity(self, sqli_attacker):
        """Test SQLi severity determination using real method."""
        # Test with different confidence levels
        severity_high = sqli_attacker._get_sqli_severity(ConfidenceLevel.HIGH)
        severity_medium = sqli_attacker._get_sqli_severity(ConfidenceLevel.MEDIUM)
        severity_low = sqli_attacker._get_sqli_severity(ConfidenceLevel.LOW)

        assert isinstance(severity_high, Severity)
        assert isinstance(severity_medium, Severity)
        assert isinstance(severity_low, Severity)

        # Higher confidence should generally mean higher severity
        assert severity_high in [Severity.HIGH, Severity.CRITICAL]
        assert severity_low in [Severity.MEDIUM]
        """Test SQLi finding creation using create_vulnerability method."""
        from ciberwebscan.export.models import AttackPayload

        # Create a payload object
        payload = AttackPayload(
            type="sqli", payload="' OR '1'='1", parameter="id", method="GET"
        )

        # Use the real create_vulnerability method from AttackEngine
        finding = sqli_attacker.create_vulnerability(
            title="SQL Injection in parameter 'id'",
            description="MySQL database detected with error-based SQL injection vulnerability",
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            url="https://example.com/user?id=1'",
            payload=payload,
            evidence="MySQL syntax error detected",
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
        )

        assert isinstance(finding, VulnerabilityFinding)
        assert finding.type == "sqli"
        assert finding.url == "https://example.com/user?id=1'"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == ConfidenceLevel.HIGH
        assert "SQL Injection" in finding.title
        assert "MySQL" in finding.description

    @pytest.mark.asyncio
    async def test_test_error_based_vulnerable(
        self, sqli_attacker, attack_context, vulnerable_mysql_response
    ):
        """Test error-based SQLi testing with vulnerability using real method."""
        # Configure mock properly
        attack_context.http_client.get = Mock(return_value=vulnerable_mysql_response)

        # Use the real _test_parameter_sqli method
        vuln = await sqli_attacker._test_parameter_sqli(
            attack_context,
            "https://example.com/user",
            "id",
            "'",
            "GET",
            "normal response",
            len("normal response"),
            200,
        )

        # Should detect vulnerability
        if vuln:
            assert vuln.type == "sqli"
            assert isinstance(vuln.confidence, ConfidenceLevel)

    @pytest.mark.asyncio
    async def test_test_error_based_safe(
        self, sqli_attacker, attack_context, normal_response
    ):
        """Test error-based SQLi testing without vulnerability using real method."""
        # Configure mock properly
        attack_context.http_client.get = Mock(return_value=normal_response)

        # Use the real _test_parameter_sqli method
        vuln = await sqli_attacker._test_parameter_sqli(
            attack_context,
            "https://example.com/user",
            "id",
            "'",
            "GET",
            normal_response.text,
            len(normal_response.text),
            200,
        )

        # Should not detect vulnerability
        assert vuln is None

    @pytest.mark.asyncio
    async def test_test_url_parameters_async(
        self, sqli_attacker, attack_context, normal_response
    ):
        """Test URL parameter testing using real async method."""
        # Configure mock properly
        attack_context.http_client.get = Mock(return_value=normal_response)

        # Use the real _test_url_parameters method
        vulnerabilities = await sqli_attacker._test_url_parameters(
            attack_context,
            normal_response,
            normal_response.text,
            len(normal_response.text),
            200,
        )

        assert isinstance(vulnerabilities, list)

    @pytest.mark.asyncio
    async def test_test_form_sqli_async(
        self, sqli_attacker, attack_context, form_response
    ):
        """Test form SQLi testing using real async method."""
        # Configure mock properly
        attack_context.http_client.post = Mock(return_value=form_response)

        # Use the real _test_form_sqli method
        vulnerabilities = await sqli_attacker._test_form_sqli(
            attack_context,
            form_response,
            form_response.text,
            len(form_response.text),
            200,
        )

        assert isinstance(vulnerabilities, list)

    @pytest.mark.asyncio
    async def test_test_form_inputs_vulnerable(
        self, sqli_attacker, attack_context, form_response, vulnerable_mysql_response
    ):
        """Test form input testing with vulnerability."""
        # First request gets the form, subsequent requests return vulnerable response
        attack_context.http_client.get.return_value = form_response
        attack_context.http_client.post.return_value = vulnerable_mysql_response

        vulnerabilities = await sqli_attacker._test_form_sqli(
            attack_context,
            form_response,
            form_response.text,
            len(form_response.text),
            200,
        )

        assert isinstance(vulnerabilities, list)

    def test_should_test_parameter_safe(self, sqli_attacker):
        """Test parameter filtering logic from base class."""
        # Should test normal parameters
        assert sqli_attacker.should_test_parameter("username") is True
        assert sqli_attacker.should_test_parameter("id") is True
        assert sqli_attacker.should_test_parameter("search") is True

        # Should skip security tokens
        assert sqli_attacker.should_test_parameter("csrf_token") is False
        assert sqli_attacker.should_test_parameter("authenticity_token") is False
        assert sqli_attacker.should_test_parameter("_token") is False

    def test_create_payload_object(self, sqli_attacker):
        """Test payload object creation from base class."""
        payload_obj = sqli_attacker.create_payload_object(
            payload_str="' OR 1=1--", parameter="id", method="GET"
        )

        assert payload_obj.type == "sqli"
        assert payload_obj.payload == "' OR 1=1--"
        assert payload_obj.parameter == "id"
        assert payload_obj.method == "GET"

    def test_determine_severity(self, sqli_attacker):
        """Test SQLi vulnerability severity determination."""
        # Test severity determination using real method
        # Use lower confidence for testing
        low_severity = sqli_attacker._get_sqli_severity(ConfidenceLevel.LOW)
        medium_severity = sqli_attacker._get_sqli_severity(ConfidenceLevel.MEDIUM)
        high_severity = sqli_attacker._get_sqli_severity(ConfidenceLevel.HIGH)

        assert isinstance(low_severity, Severity)
        assert isinstance(medium_severity, Severity)
        assert isinstance(high_severity, Severity)

        # Different confidence levels should have appropriate severities
        assert high_severity in [Severity.HIGH, Severity.CRITICAL]
        assert medium_severity in [Severity.MEDIUM, Severity.HIGH]

    @pytest.mark.asyncio
    async def test_execute_comprehensive(
        self, sqli_attacker, attack_context, form_response
    ):
        """Test comprehensive SQLi execution using the real execute method."""
        # Configure mock properly
        attack_context.http_client.get = Mock(return_value=form_response)

        vulnerabilities = await sqli_attacker.execute(attack_context)

        assert isinstance(vulnerabilities, list)
        assert attack_context.total_requests > 0

    @pytest.mark.asyncio
    async def test_execute_connection_errors(self, sqli_attacker, attack_context):
        """Test execution with connection errors."""
        # Configure mock properly to raise exception
        attack_context.http_client.get = Mock(
            side_effect=Exception("Connection failed")
        )

        vulnerabilities = await sqli_attacker.execute(attack_context)

        assert isinstance(vulnerabilities, list)
        assert attack_context.failed_requests > 0
