"""
Tests for CSRF attack module.
"""

from unittest.mock import Mock

import pytest

from ciberwebscan.core.attacks.base import AttackConfig, AttackContext, AttackIntensity
from ciberwebscan.core.attacks.csrf import CSRFAttacker
from ciberwebscan.core.client import HTTPClient
from ciberwebscan.export.models import (
    ConfidenceLevel,
    Severity,
)


@pytest.fixture
def csrf_attacker():
    """CSRF attacker instance."""
    return CSRFAttacker()


@pytest.fixture
def attack_config():
    """Basic attack configuration for CSRF."""
    return AttackConfig(
        target_url="https://example.com/form",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=10,
        timeout=5.0,
        user_consent=True,
    )


@pytest.fixture
def http_client_mock():
    """Mocked HTTP client for CSRF tests."""
    client = Mock(spec=HTTPClient)
    client.get = Mock()
    client.post = Mock()
    return client


@pytest.fixture
def attack_context(attack_config, http_client_mock):
    """Attack context for CSRF tests."""
    return AttackContext(config=attack_config, http_client=http_client_mock)


@pytest.fixture
def form_without_csrf():
    """Mock response with a POST form without CSRF token."""
    response = Mock()
    response.url = "https://example.com/contact"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <form action="/submit" method="POST">
                <input type="text" name="title" />
                <input type="text" name="comment" />
                <textarea name="message"></textarea>
                <input type="submit" value="Send" />
            </form>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def form_with_csrf():
    """Mock response with a POST form that has a CSRF token."""
    response = Mock()
    response.url = "https://example.com/contact"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <form action="/submit" method="POST">
                <input type="hidden" name="csrf_token" value="abc123" />
                <input type="text" name="username" />
                <input type="email" name="email" />
                <textarea name="message"></textarea>
                <input type="submit" value="Send" />
            </form>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def get_form_response():
    """Mock response with a GET form (not vulnerable to CSRF)."""
    response = Mock()
    response.url = "https://example.com/search"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <form action="/search" method="GET">
                <input type="text" name="q" />
                <input type="submit" value="Search" />
            </form>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def sensitive_form_response():
    """Mock response with a sensitive POST form without CSRF token."""
    response = Mock()
    response.url = "https://example.com/admin"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <form action="/admin/delete" method="POST">
                <input type="hidden" name="user_id" value="123" />
                <input type="password" name="password" />
                <input type="submit" value="Delete User" />
            </form>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def no_form_response():
    """Mock response with no forms."""
    response = Mock()
    response.url = "https://example.com/about"
    response.status_code = 200
    response.text = """
    <html>
        <body>
            <h1>About Us</h1>
            <p>This is a static page with no forms.</p>
        </body>
    </html>
    """
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/html"}
    return response


class TestCSRFAttacker:
    """Tests for CSRFAttacker class."""

    def test_initialization(self, csrf_attacker):
        """Test CSRFAttacker initialization."""
        assert csrf_attacker.name == "csrf"

    def test_get_payloads(self, csrf_attacker):
        """Test getting payloads at different intensities."""
        low_payloads = csrf_attacker.get_payloads(AttackIntensity.LOW, 10)
        assert isinstance(low_payloads, list)

        medium_payloads = csrf_attacker.get_payloads(AttackIntensity.MEDIUM, 10)
        assert isinstance(medium_payloads, list)

        high_payloads = csrf_attacker.get_payloads(AttackIntensity.HIGH, 10)
        assert isinstance(high_payloads, list)

    def test_validate_target(self, csrf_attacker):
        """Test target URL validation."""
        assert csrf_attacker.validate_target("https://example.com")
        assert csrf_attacker.validate_target("http://example.com")
        assert not csrf_attacker.validate_target("ftp://example.com")
        assert not csrf_attacker.validate_target("not-a-url")

    @pytest.mark.asyncio
    async def test_execute_with_form_without_csrf(
        self, csrf_attacker, attack_context, form_without_csrf
    ):
        """Test execute finds CSRF vulnerability in form without token."""
        attack_context.http_client.get.return_value = form_without_csrf

        findings = await csrf_attacker.execute(attack_context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.type == "csrf"
        assert finding.title == "Formulario POST sin token CSRF"
        assert finding.severity == Severity.MEDIUM
        assert finding.confidence == ConfidenceLevel.HIGH
        assert finding.cwe_id == "CWE-352"
        assert finding.url == "https://example.com/submit"

    @pytest.mark.asyncio
    async def test_execute_with_form_with_csrf(
        self, csrf_attacker, attack_context, form_with_csrf
    ):
        """Test execute finds no vulnerability in form with CSRF token."""
        attack_context.http_client.get.return_value = form_with_csrf

        findings = await csrf_attacker.execute(attack_context)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_execute_with_get_form(
        self, csrf_attacker, attack_context, get_form_response
    ):
        """Test execute finds no vulnerability in GET form."""
        attack_context.http_client.get.return_value = get_form_response

        findings = await csrf_attacker.execute(attack_context)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_execute_with_sensitive_form(
        self, csrf_attacker, attack_context, sensitive_form_response
    ):
        """Test execute finds HIGH severity for sensitive form without CSRF token."""
        attack_context.http_client.get.return_value = sensitive_form_response

        findings = await csrf_attacker.execute(attack_context)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.type == "csrf"
        assert finding.severity == Severity.HIGH
        assert (
            "password" in finding.evidence.lower()
            or "password" in finding.description.lower()
        )

    @pytest.mark.asyncio
    async def test_execute_with_no_forms(
        self, csrf_attacker, attack_context, no_form_response
    ):
        """Test execute finds no vulnerabilities when no forms present."""
        attack_context.http_client.get.return_value = no_form_response

        findings = await csrf_attacker.execute(attack_context)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_execute_with_failed_request(self, csrf_attacker, attack_context):
        """Test execute handles failed HTTP request gracefully."""
        attack_context.http_client.get.return_value = None

        findings = await csrf_attacker.execute(attack_context)

        assert len(findings) == 0

    def test_analyze_form_post_without_csrf(self, csrf_attacker):
        """Test _analyze_form with POST form without CSRF token."""
        form = {
            "action": "/submit",
            "method": "POST",
            "inputs": [
                {"name": "title", "type": "text", "value": ""},
                {"name": "comment", "type": "text", "value": ""},
            ],
        }

        finding = csrf_attacker._analyze_form(form, "https://example.com")

        assert finding is not None
        assert finding.type == "csrf"
        assert finding.severity == Severity.MEDIUM

    def test_analyze_form_post_with_csrf(self, csrf_attacker):
        """Test _analyze_form with POST form that has CSRF token."""
        form = {
            "action": "/submit",
            "method": "POST",
            "inputs": [
                {"name": "csrf_token", "type": "hidden", "value": "abc123"},
                {"name": "username", "type": "text", "value": ""},
            ],
        }

        finding = csrf_attacker._analyze_form(form, "https://example.com")

        assert finding is None

    def test_analyze_form_get_method(self, csrf_attacker):
        """Test _analyze_form with GET form (not vulnerable)."""
        form = {
            "action": "/search",
            "method": "GET",
            "inputs": [
                {"name": "q", "type": "text", "value": ""},
            ],
        }

        finding = csrf_attacker._analyze_form(form, "https://example.com")

        assert finding is None

    def test_analyze_form_empty_inputs(self, csrf_attacker):
        """Test _analyze_form with form that has no inputs."""
        form = {
            "action": "/submit",
            "method": "POST",
            "inputs": [],
        }

        finding = csrf_attacker._analyze_form(form, "https://example.com")

        assert finding is None

    def test_analyze_form_with_various_csrf_tokens(self, csrf_attacker):
        """Test _analyze_form recognizes various CSRF token names."""
        token_names = [
            "csrf_token",
            "_csrf",
            "authenticity_token",
            "_token",
            "__RequestVerificationToken",
            "xsrf",
            "_xsrf",
            "csrfmiddlewaretoken",
        ]

        for token_name in token_names:
            form = {
                "action": "/submit",
                "method": "POST",
                "inputs": [
                    {"name": token_name, "type": "hidden", "value": "token_value"},
                    {"name": "data", "type": "text", "value": ""},
                ],
            }

            finding = csrf_attacker._analyze_form(form, "https://example.com")
            assert finding is None, f"Token name '{token_name}' should be recognized"

    def test_determine_severity_high(self, csrf_attacker):
        """Test _determine_severity returns HIGH for sensitive fields."""
        inputs = [
            {"name": "password", "type": "password", "value": ""},
            {"name": "email", "type": "email", "value": ""},
        ]

        severity = csrf_attacker._determine_severity(inputs)
        assert severity == Severity.HIGH

    def test_determine_severity_medium(self, csrf_attacker):
        """Test _determine_severity returns MEDIUM for non-sensitive fields."""
        inputs = [
            {"name": "title", "type": "text", "value": ""},
            {"name": "comment", "type": "textarea", "value": ""},
        ]

        severity = csrf_attacker._determine_severity(inputs)
        assert severity == Severity.MEDIUM

    def test_create_vulnerability(self, csrf_attacker):
        """Test create_vulnerability helper method."""
        payload = csrf_attacker.create_payload_object(
            "NO_CSRF_TOKEN", "username", "POST"
        )

        vuln = csrf_attacker.create_vulnerability(
            title="Test CSRF",
            description="Test description",
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            url="https://example.com",
            payload=payload,
            evidence="Test evidence",
            remediation="Test remediation",
            cwe_id="CWE-352",
            owasp_category="A01:2021 - Broken Access Control",
        )

        assert vuln.type == "csrf"
        assert vuln.title == "Test CSRF"
        assert vuln.severity == Severity.MEDIUM
        assert vuln.confidence == ConfidenceLevel.HIGH
        assert vuln.cwe_id == "CWE-352"
