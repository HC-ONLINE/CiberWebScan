"""
Tests for path traversal attack module.
"""

from unittest.mock import Mock

import pytest

from ciberwebscan.core.attacks.base import AttackConfig, AttackContext, AttackIntensity
from ciberwebscan.core.attacks.traversal import PathTraversalAttacker
from ciberwebscan.core.client import HTTPClient
from ciberwebscan.export.models import (
    ConfidenceLevel,
)


@pytest.fixture
def traversal_attacker():
    """Path traversal attacker instance."""
    return PathTraversalAttacker()


@pytest.fixture
def attack_config():
    """Basic attack configuration for path traversal."""
    return AttackConfig(
        target_url="https://example.com/files",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=15,
        timeout=5.0,
        user_consent=True,
    )


@pytest.fixture
def http_client_mock():
    """Mocked HTTP client for path traversal tests."""
    client = Mock(spec=HTTPClient)
    client.get = Mock()
    client.post = Mock()
    return client


@pytest.fixture
def attack_context(attack_config, http_client_mock):
    """Attack context for path traversal tests."""
    return AttackContext(config=attack_config, http_client=http_client_mock)


@pytest.fixture
def vulnerable_etc_passwd_response():
    """Mock response with /etc/passwd content."""
    response = Mock()
    response.url = "https://example.com/files?file=../../etc/passwd"
    response.status_code = 200
    response.text = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"""
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/plain"}
    return response


@pytest.fixture
def vulnerable_windows_response():
    """Mock response with windows system file content."""
    response = Mock()
    response.url = (
        "https://example.com/view?path=..\\..\\windows\\system32\\drivers\\etc\\hosts"
    )
    response.status_code = 200
    response.text = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.

127.0.0.1       localhost
::1             localhost"""
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/plain"}
    return response


@pytest.fixture
def vulnerable_config_response():
    """Mock response with application config file."""
    response = Mock()
    response.url = "https://example.com/download?file=../../../app/config/database.yml"
    response.status_code = 200
    response.text = """production:
  adapter: mysql2
  database: production_db
  username: prod_user
  password: super_secret_password
  host: db.internal.com
  port: 3306

development:
  adapter: sqlite3
  database: db/development.sqlite3"""
    response.content = response.text.encode()
    response.headers = {"Content-Type": "text/yaml"}
    return response


@pytest.fixture
def safe_response():
    """Mock safe response without traversal indicators."""
    response = Mock()
    response.url = "https://example.com/files?file=document.pdf"
    response.status_code = 200
    response.text = "Normal document content here"
    response.content = b"Normal document content here"
    response.headers = {"Content-Type": "application/pdf"}
    return response


@pytest.fixture
def error_response():
    """Mock error response."""
    response = Mock()
    response.url = "https://example.com/files?file=../invalid"
    response.status_code = 404
    response.text = "File not found"
    response.content = b"File not found"
    response.headers = {"Content-Type": "text/html"}
    return response


class TestPathTraversalAttacker:
    """Test PathTraversalAttacker functionality."""

    def test_initialization(self, traversal_attacker):
        """Test path traversal attacker initialization."""
        assert traversal_attacker.name == "traversal"
        assert hasattr(traversal_attacker, "payload_loader")
        # Check that attacker has expected attributes
        assert hasattr(traversal_attacker, "success_signatures")
        # Verify basic functionality instead of specific internal attributes
        assert traversal_attacker.validate_target("https://example.com") is True

    def test_get_payloads_basic(self, traversal_attacker):
        """Test basic payload generation."""
        payloads = traversal_attacker.get_payloads(AttackIntensity.LOW, 5)

        assert isinstance(payloads, list)
        assert len(payloads) <= 5
        assert all(isinstance(p, str) for p in payloads)

        # Should contain basic traversal patterns
        has_dotdot = any(".." in p for p in payloads)
        assert has_dotdot

    def test_get_payloads_advanced(self, traversal_attacker):
        """Test advanced payload generation."""
        payloads = traversal_attacker.get_payloads(AttackIntensity.HIGH, 20)

        assert isinstance(payloads, list)
        assert len(payloads) <= 20

        # Should contain varied traversal techniques
        techniques = {
            "basic": any("../" in p for p in payloads),
            "encoded": any("%2e%2e" in p.lower() for p in payloads),
            "windows": any("..\\" in p for p in payloads),
            "absolute": any(p.startswith("/") for p in payloads),
        }

        assert sum(techniques.values()) >= 2  # Multiple techniques

    def test_validate_target(self, traversal_attacker):
        """Test target URL validation."""
        assert traversal_attacker.validate_target("https://example.com") is True
        assert traversal_attacker.validate_target("http://example.com/files") is True
        assert traversal_attacker.validate_target("ftp://example.com") is False
        assert traversal_attacker.validate_target("invalid-url") is False

    def test_analyze_traversal_response_unix(
        self, traversal_attacker, vulnerable_etc_passwd_response
    ):
        """Test traversal response analysis using real method."""
        confidence, evidence = traversal_attacker._analyze_traversal_response(
            vulnerable_etc_passwd_response.content,
            vulnerable_etc_passwd_response.text,
            "../../etc/passwd",
        )

        assert isinstance(confidence, ConfidenceLevel)
        # Should detect the Unix file exposure
        assert confidence != ConfidenceLevel.LOW
        assert isinstance(evidence, str)
        assert "root" in evidence.lower() or "passwd" in evidence.lower()

    def test_analyze_traversal_response_windows(
        self, traversal_attacker, vulnerable_windows_response
    ):
        """Test Windows traversal response analysis using real method."""
        confidence, evidence = traversal_attacker._analyze_traversal_response(
            vulnerable_windows_response.content,
            vulnerable_windows_response.text,
            "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        )

        assert isinstance(confidence, ConfidenceLevel)
        # Should detect the Windows file exposure
        assert confidence != ConfidenceLevel.LOW
        assert isinstance(evidence, str)
        assert "127.0.0.1" in evidence or "localhost" in evidence

    def test_detect_config_file_exposure(
        self, traversal_attacker, vulnerable_config_response
    ):
        """Basic check that config-like responses are analyzed without error."""
        confidence, evidence = traversal_attacker._analyze_traversal_response(
            vulnerable_config_response.content,
            vulnerable_config_response.text,
            "../../../app/config/database.yml",
        )

        assert isinstance(confidence, ConfidenceLevel)
        assert isinstance(evidence, str)

    def test_detect_no_exposure(self, traversal_attacker, safe_response):
        """Test no file exposure detection."""
        confidence, evidence = traversal_attacker._analyze_traversal_response(
            safe_response.content,
            safe_response.text,
            "../etc/passwd",
        )

        assert confidence == ConfidenceLevel.LOW
        assert evidence == ""

    def test_analyze_path_structure(self, traversal_attacker):
        """Test path structure analysis."""
        # The implementation exposes _is_file_parameter; validate common file-like names
        assert traversal_attacker._is_file_parameter("file") is True
        assert traversal_attacker._is_file_parameter("path") is True
        assert traversal_attacker._is_file_parameter("template") is True

    def test_basic_payloads_and_execution(
        self, traversal_attacker, attack_context, safe_response
    ):
        """Minimal checks for payload generation and execution flow."""
        # get_payloads should return a list and contain traversal patterns
        payloads = traversal_attacker.get_payloads(AttackIntensity.MEDIUM, 10)
        assert isinstance(payloads, list)
        assert any(".." in p or "%2e%2e" in p.lower() for p in payloads)

        # Execute should run without raising when client returns a safe response
        attack_context.http_client.get.return_value = safe_response
        attack_context.http_client.post.return_value = safe_response

        # Run execute (async) to ensure integration path works
        async def _run_execute():
            return await traversal_attacker.execute(attack_context)

        import asyncio

        vulnerabilities = asyncio.get_event_loop().run_until_complete(_run_execute())
        assert isinstance(vulnerabilities, list)
