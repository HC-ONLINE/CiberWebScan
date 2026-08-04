"""
Subdomain enumeration.

Discovery of active subdomains through wordlist-based brute force
using DNS resolution.
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import uuid
from urllib.parse import urlparse

from ciberwebscan.export.models import (
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)

from .base import AttackContext, AttackEngine, AttackIntensity
from .payloads import PayloadLoader

logger = logging.getLogger(__name__)


class SubdomainEnumerator(AttackEngine):
    """Subdomain enumeration engine based on DNS brute force."""

    def __init__(self):
        super().__init__("subdomain")
        self.payload_loader = PayloadLoader()

    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Get subdomain wordlist based on intensity level."""
        return self.payload_loader.get_payloads("subdomain", intensity, max_count)

    async def execute(
        self,
        context: AttackContext,
        custom_wordlist: str | None = None,
    ) -> list[VulnerabilityFinding]:
        """Execute subdomain enumeration."""
        self.logger.info(
            f"Starting subdomain enumeration on {context.config.target_url}"
        )

        domain = self._extract_domain(context.config.target_url)
        if not domain:
            self.logger.warning(
                "Target is not a valid domain (IP targets are not supported): "
                f"{context.config.target_url}"
            )
            return []

        # Detect wildcard DNS to avoid false positives
        wildcard = self._detect_wildcard_dns(domain)
        if wildcard:
            self.logger.warning(
                f"Wildcard DNS detected for {domain}: every subdomain resolves. "
                "Results may be unreliable."
            )

        # Get wordlist
        wordlist = self.get_payloads(
            context.config.intensity, context.config.max_payloads
        )

        # Apply custom wordlist if provided
        if custom_wordlist:
            wordlist = self._load_custom_wordlist(custom_wordlist, wordlist)

        found_subdomains = await self._bruteforce(context, domain, wordlist, wildcard)

        vulnerabilities = self._build_findings(domain, found_subdomains)

        self.logger.info(
            f"Subdomain enumeration completed. Found {len(vulnerabilities)} active subdomains"
        )
        return vulnerabilities

    def _extract_domain(self, target_url: str) -> str | None:
        """Extract the root domain from a target URL."""
        try:
            parsed = urlparse(
                target_url if "://" in target_url else f"http://{target_url}"
            )
            hostname = parsed.hostname or ""
        except ValueError:
            return None
        hostname = hostname.lower().strip(".")
        if not hostname:
            return None
        # Must be a valid hostname (letters, digits, hyphens, dots)
        if not all(c.isalnum() or c in ".-" for c in hostname):
            return None
        if not any(c.isalnum() for c in hostname):
            return None
        return hostname

    def _detect_wildcard_dns(self, domain: str) -> bool:
        """Check if the domain has wildcard DNS enabled."""
        probe = f"cws-{uuid.uuid4().hex[:12]}.{domain}"
        return self._resolve(probe) is not None

    def _resolve(self, hostname: str) -> str | None:
        """Resolve a hostname to its IP address (or None on failure)."""
        try:
            infos = socket.getaddrinfo(
                hostname, None, socket.AF_INET, socket.SOCK_STREAM
            )
            if infos:
                address = infos[0][4][0]
                if isinstance(address, str):
                    return address
        except (socket.gaierror, TimeoutError, OSError):
            return None
        return None

    def _load_custom_wordlist(
        self, custom_wordlist: str, default: list[str]
    ) -> list[str]:
        """Load custom subdomain wordlist from a file (one per line)."""
        try:
            with open(custom_wordlist, encoding="utf-8") as f:
                words = [line.strip() for line in f if line.strip()]
            if words:
                self.logger.info(
                    f"Loaded {len(words)} custom subdomains from {custom_wordlist}"
                )
                return words
        except OSError as e:
            self.logger.warning(f"Could not load custom wordlist: {e}")
        return default

    async def _bruteforce(
        self,
        context: AttackContext,
        domain: str,
        wordlist: list[str],
        wildcard: bool,
    ) -> list[tuple[str, str]]:
        """Brute force candidate subdomains and return resolved ones."""
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        semaphore = asyncio.Semaphore(context.config.concurrent_requests)

        # Randomize to avoid obvious order-based detection
        candidates = random.sample(wordlist, len(wordlist))

        async def test_candidate(candidate: str) -> None:
            async with semaphore:
                hostname = f"{candidate}.{domain}"
                ip = await asyncio.to_thread(self._resolve, hostname)
                if ip is None:
                    context.log_request(False)
                else:
                    context.log_request(True)
                    if not wildcard and hostname not in seen:
                        seen.add(hostname)
                        found.append((hostname, ip))
                        self.logger.info(f"Subdomain found: {hostname} ({ip})")

                if context.config.delay_between_requests > 0:
                    await asyncio.sleep(context.config.delay_between_requests)

        batch_size = 10
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i : i + batch_size]
            await asyncio.gather(
                *(test_candidate(c) for c in batch), return_exceptions=True
            )

        return found

    def _build_findings(
        self, domain: str, found: list[tuple[str, str]]
    ) -> list[VulnerabilityFinding]:
        """Build VulnerabilityFinding objects for discovered subdomains."""
        findings = []
        for hostname, ip in found:
            attack_payload = self.create_payload_object(hostname, "subdomain", "DNS")
            findings.append(
                self.create_vulnerability(
                    title=f"Active subdomain found: {hostname}",
                    description=(
                        f"Subdomain '{hostname}' resolves to a live host. "
                        "It may expose additional attack surface for the target domain."
                    ),
                    severity=Severity.INFO,
                    confidence=ConfidenceLevel.HIGH,
                    url=f"https://{hostname}",
                    payload=attack_payload,
                    evidence=f"Resolved: {hostname} -> {ip}",
                    remediation=(
                        "Remove unused subdomains or restrict access to reduce "
                        "the attack surface."
                    ),
                    cwe_id="CWE-200",
                    owasp_category="A01:2021 - Broken Access Control",
                )
            )
        return findings
