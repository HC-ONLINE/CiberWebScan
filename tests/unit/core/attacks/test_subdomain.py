"""
Tests for subdomain enumeration attack module.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from ciberwebscan.core.attacks.base import AttackConfig, AttackContext, AttackIntensity
from ciberwebscan.core.attacks.subdomain import SubdomainEnumerator
from ciberwebscan.export.models import Severity, VulnerabilityFinding


@pytest.fixture
def enumerator():
    """Subdomain enumerator instance."""
    return SubdomainEnumerator()


@pytest.fixture
def attack_config():
    """Basic attack configuration for subdomain enumeration."""
    return AttackConfig(
        target_url="https://example.com",
        intensity=AttackIntensity.MEDIUM,
        max_payloads=10,
        timeout=5.0,
        user_consent=True,
        concurrent_requests=3,
        delay_between_requests=0.0,
    )


@pytest.fixture
def attack_context(attack_config):
    """Attack context for subdomain tests."""
    return AttackContext(config=attack_config, http_client=Mock())


class TestSubdomainEnumerator:
    """Test SubdomainEnumerator functionality."""

    def test_initialization(self, enumerator):
        """Test enumerator initialization."""
        assert enumerator.name == "subdomain"
        assert hasattr(enumerator, "payload_loader")

    def test_get_payloads(self, enumerator):
        """Test payload generation by intensity."""
        payloads = enumerator.get_payloads(AttackIntensity.LOW, 50)
        assert isinstance(payloads, list)
        assert all(isinstance(p, str) for p in payloads)

    def test_validate_target(self, enumerator):
        """Test target URL validation."""
        assert enumerator.validate_target("https://example.com") is True
        assert enumerator.validate_target("http://example.com") is True
        assert enumerator.validate_target("ftp://example.com") is False

    def test_extract_domain(self, enumerator):
        """Test domain extraction from URLs."""
        assert (
            enumerator._extract_domain("https://example.com/path?q=1") == "example.com"
        )
        assert enumerator._extract_domain("http://sub.example.com") == "sub.example.com"
        assert enumerator._extract_domain("example.com") == "example.com"
        assert enumerator._extract_domain("not a url") is None

    @pytest.mark.asyncio
    async def test_execute_no_wildcard_finds_subdomains(
        self, enumerator, attack_context
    ):
        """Test execution discovers resolving subdomains."""
        resolved = {
            "www.example.com": "93.184.216.34",
            "mail.example.com": "93.184.216.35",
        }

        def fake_resolve(hostname: str) -> str | None:
            if hostname.startswith("cws-"):
                return None  # wildcard probe does not resolve
            return resolved.get(hostname)

        with patch.object(enumerator, "_resolve", side_effect=fake_resolve):
            vulnerabilities = await enumerator.execute(attack_context)

        assert isinstance(vulnerabilities, list)
        assert len(vulnerabilities) > 0
        for vuln in vulnerabilities:
            assert isinstance(vuln, VulnerabilityFinding)
            assert vuln.type == "subdomain"
            assert vuln.severity == Severity.INFO
            assert vuln.confidence.value == "high"
            assert vuln.payload.parameter == "subdomain"
            assert vuln.payload.method == "DNS"
            assert "Resolved:" in vuln.evidence

    @pytest.mark.asyncio
    async def test_execute_none_resolve(self, enumerator, attack_context):
        """Test execution with no resolving subdomains."""
        with patch.object(enumerator, "_resolve", return_value=None):
            vulnerabilities = await enumerator.execute(attack_context)

        assert vulnerabilities == []
        assert attack_context.total_requests > 0

    @pytest.mark.asyncio
    async def test_execute_wildcard_dns(self, enumerator, attack_context):
        """Test wildcard DNS yields no findings."""
        with patch.object(enumerator, "_resolve", return_value="1.2.3.4"):
            vulnerabilities = await enumerator.execute(attack_context)

        assert vulnerabilities == []

    @pytest.mark.asyncio
    async def test_execute_ip_target(self, enumerator, attack_context):
        """Test execution against an IP target returns no findings."""
        attack_context.config.target_url = "https://127.0.0.1"
        with patch.object(enumerator, "_resolve", return_value=None):
            vulnerabilities = await enumerator.execute(attack_context)

        assert vulnerabilities == []

    @pytest.mark.asyncio
    async def test_execute_custom_wordlist(self, enumerator, attack_context, tmp_path):
        """Test custom wordlist loading."""
        wordlist_file = tmp_path / "subs.txt"
        wordlist_file.write_text("api\nstatus\n")

        def fake_resolve(hostname: str) -> str | None:
            if hostname == "api.example.com":
                return "10.0.0.1"
            return None

        with patch.object(enumerator, "_resolve", side_effect=fake_resolve):
            vulnerabilities = await enumerator.execute(
                attack_context, custom_wordlist=str(wordlist_file)
            )

        assert len(vulnerabilities) == 1
        assert "api.example.com" in vulnerabilities[0].title
