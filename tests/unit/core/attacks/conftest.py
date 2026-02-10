"""
Pytest configuration and shared fixtures for attack module tests.
"""

from pathlib import Path
from unittest.mock import Mock

import pytest

from ciberwebscan.core.attacks.base import AttackConfig, AttackContext, AttackIntensity
from ciberwebscan.core.client.http_client import HTTPClient


@pytest.fixture(scope="session")
def test_data_dir():
    """Path to test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture
def basic_attack_config():
    """Basic attack configuration for all tests."""
    return AttackConfig(
        target_url="https://example.com",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=10,
        timeout=5.0,
        user_consent=True,
        concurrent_requests=2,
        delay_between_requests=0.1,
    )


@pytest.fixture
def high_intensity_config():
    """High intensity attack configuration."""
    return AttackConfig(
        target_url="https://example.com",
        intensity=AttackIntensity.HIGH,
        max_payloads=50,
        timeout=10.0,
        user_consent=True,
        concurrent_requests=5,
        delay_between_requests=0.05,
    )


@pytest.fixture
def low_intensity_config():
    """Low intensity attack configuration."""
    return AttackConfig(
        target_url="https://example.com",
        intensity=AttackIntensity.LOW,
        max_payloads=3,
        timeout=3.0,
        user_consent=True,
        concurrent_requests=1,
        delay_between_requests=0.5,
    )


@pytest.fixture
def mock_http_client():
    """Mock HTTP client with common response patterns."""
    client = Mock(spec=HTTPClient)

    # Configure methods as synchronous mocks (HTTPClient is sync)
    client.get = Mock()
    client.post = Mock()
    client.put = Mock()
    client.delete = Mock()
    client.head = Mock()
    client.options = Mock()

    # Configure sync methods
    client.close = Mock()

    return client


@pytest.fixture
def attack_context_factory():
    """Factory for creating attack contexts with different configurations."""

    def _create_context(config=None, http_client=None):
        if config is None:
            config = AttackConfig(
                target_url="https://example.com",
                intensity=AttackIntensity.MEDIUM,
                max_payloads=10,
                timeout=5.0,
                user_consent=True,
            )

        if http_client is None:
            http_client = Mock(spec=HTTPClient)
            http_client.get = Mock()
            http_client.post = Mock()

        return AttackContext(config=config, http_client=http_client)

    return _create_context


@pytest.fixture
def sample_responses():
    """Collection of sample HTTP responses for testing."""
    responses = {}

    # Normal successful response
    normal_response = Mock()
    normal_response.status_code = 200
    normal_response.url = "https://example.com"
    normal_response.text = "<html><body>Normal page content</body></html>"
    normal_response.content = normal_response.text.encode()
    normal_response.headers = {"Content-Type": "text/html"}
    normal_response.elapsed.total_seconds.return_value = 0.5
    responses["normal"] = normal_response

    # Error response
    error_response = Mock()
    error_response.status_code = 500
    error_response.url = "https://example.com"
    error_response.text = "Internal Server Error"
    error_response.content = error_response.text.encode()
    error_response.headers = {"Content-Type": "text/html"}
    error_response.elapsed.total_seconds.return_value = 1.0
    responses["error"] = error_response

    # Not found response
    notfound_response = Mock()
    notfound_response.status_code = 404
    notfound_response.url = "https://example.com/notfound"
    notfound_response.text = "Page Not Found"
    notfound_response.content = notfound_response.text.encode()
    notfound_response.headers = {"Content-Type": "text/html"}
    notfound_response.elapsed.total_seconds.return_value = 0.3
    responses["notfound"] = notfound_response

    # Forbidden response
    forbidden_response = Mock()
    forbidden_response.status_code = 403
    forbidden_response.url = "https://example.com/admin"
    forbidden_response.text = "Access Forbidden"
    forbidden_response.content = forbidden_response.text.encode()
    forbidden_response.headers = {"Content-Type": "text/html"}
    forbidden_response.elapsed.total_seconds.return_value = 0.4
    responses["forbidden"] = forbidden_response

    # Redirect response
    redirect_response = Mock()
    redirect_response.status_code = 302
    redirect_response.url = "https://example.com/login"
    redirect_response.text = "Found"
    redirect_response.content = redirect_response.text.encode()
    redirect_response.headers = {
        "Content-Type": "text/html",
        "Location": "https://example.com/dashboard",
    }
    redirect_response.elapsed.total_seconds.return_value = 0.2
    responses["redirect"] = redirect_response

    return responses


@pytest.fixture
def sample_forms():
    """Collection of sample HTML forms for testing."""
    forms = {}

    # Login form
    forms["login"] = """
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

    # Search form
    forms["search"] = """
    <html>
        <body>
            <form action="/search" method="get">
                <input type="text" name="q" placeholder="Search..." />
                <select name="category">
                    <option value="all">All</option>
                    <option value="news">News</option>
                    <option value="products">Products</option>
                </select>
                <input type="submit" value="Search" />
            </form>
        </body>
    </html>
    """

    # Contact form
    forms["contact"] = """
    <html>
        <body>
            <form action="/contact" method="post">
                <input type="text" name="name" required />
                <input type="email" name="email" required />
                <textarea name="message" rows="5"></textarea>
                <input type="hidden" name="token" value="abc123" />
                <input type="submit" value="Send Message" />
            </form>
        </body>
    </html>
    """

    # File upload form
    forms["upload"] = """
    <html>
        <body>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="file" />
                <input type="text" name="description" />
                <input type="submit" value="Upload" />
            </form>
        </body>
    </html>
    """

    return forms


@pytest.fixture(autouse=True)
def reset_attack_context():
    """Reset attack context state between tests."""
    yield
    # Any cleanup if needed


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (may take longer to run)"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line(
        "markers", "network: marks tests that require network access"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test items during collection."""
    for item in items:
        # Add 'unit' marker to all tests by default
        if not any(
            mark.name in ["integration", "network"] for mark in item.iter_markers()
        ):
            item.add_marker(pytest.mark.unit)


# Mock data for common test scenarios
SAMPLE_PAYLOADS = {
    "xss": [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "' onerror='alert(1)'",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
    ],
    "sqli": [
        "'",
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' AND SLEEP(5)--",
    ],
    "traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "enumeration": ["admin", "backup", "config", "test", "upload"],
}


@pytest.fixture
def sample_payloads():
    """Sample payloads for different attack types."""
    return SAMPLE_PAYLOADS
