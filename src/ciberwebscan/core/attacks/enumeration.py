"""
Directory and file enumeration.

Discovery of hidden directories, files, and resources through
wordlist-based brute force enumeration.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin

from ciberwebscan.export.models import (
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)

from .base import AttackContext, AttackEngine, AttackIntensity
from .payloads import PayloadLoader

logger = logging.getLogger(__name__)


class DirectoryEnumerator(AttackEngine):
    """Directory and file enumeration engine."""

    def __init__(self):
        super().__init__("enumeration")
        self.payload_loader = PayloadLoader()

        # Interesting status codes to investigate
        self.interesting_codes = {200, 301, 302, 403, 401}

        # Common file extensions to test
        self.common_extensions = [
            "",
            ".php",
            ".html",
            ".htm",
            ".asp",
            ".aspx",
            ".jsp",
            ".do",
            ".txt",
            ".xml",
            ".json",
            ".js",
            ".css",
            ".sql",
            ".bak",
            ".old",
            ".orig",
            ".backup",
            ".zip",
            ".tar.gz",
            ".log",
        ]

        # Sensitive files and directories that are high priority
        self.sensitive_paths = {
            "admin",
            "administrator",
            "login",
            "dashboard",
            "control",
            "backup",
            "backups",
            "config",
            "configuration",
            "db",
            "database",
            ".env",
            ".git",
            ".svn",
            "wp-admin",
            "phpMyAdmin",
            "adminer",
            "robots.txt",
            "sitemap.xml",
            "crossdomain.xml",
            "clientaccesspolicy.xml",
        }

    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Get enumeration wordlist based on intensity level."""
        return self.payload_loader.get_payloads("enumeration", intensity, max_count)

    async def execute(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute directory enumeration."""
        self.logger.info(
            f"Starting directory enumeration on {context.config.target_url}"
        )

        vulnerabilities = []
        discovered_paths: set[str] = set()

        # Ensure target URL ends with /
        base_url = context.config.target_url.rstrip("/") + "/"

        # Get wordlist
        wordlist = self.get_payloads(
            context.config.intensity, context.config.max_payloads
        )

        # Test base paths
        base_vulns = await self._enumerate_paths(
            context, base_url, wordlist, discovered_paths
        )
        vulnerabilities.extend(base_vulns)

        # Test common files on discovered directories
        if context.config.intensity in [AttackIntensity.MEDIUM, AttackIntensity.HIGH]:
            file_vulns = await self._enumerate_files(context, discovered_paths)
            vulnerabilities.extend(file_vulns)

        # Test for sensitive files in root
        sensitive_vulns = await self._test_sensitive_files(context, base_url)
        vulnerabilities.extend(sensitive_vulns)

        self.logger.info(
            f"Directory enumeration completed. Found {len(vulnerabilities)} items"
        )
        return vulnerabilities

    async def _enumerate_paths(
        self,
        context: AttackContext,
        base_url: str,
        wordlist: list[str],
        discovered_paths: set[str],
    ) -> list[VulnerabilityFinding]:
        """Enumerate directory paths using wordlist."""
        vulnerabilities = []
        semaphore = asyncio.Semaphore(context.config.concurrent_requests)

        async def test_path(path: str) -> VulnerabilityFinding | None:
            async with semaphore:
                test_url = urljoin(base_url, path)

                response = await self.send_request(context, test_url)
                if not response:
                    return None

                # Check for interesting responses
                if response.status_code in self.interesting_codes:
                    discovered_paths.add(test_url)

                    finding_type, severity, description = self._analyze_response(
                        response.status_code, path, response
                    )

                    if finding_type:
                        attack_payload = self.create_payload_object(
                            path, "directory", "GET"
                        )

                        return self.create_vulnerability(
                            title=f"{finding_type}: {path}",
                            description=description,
                            severity=severity,
                            confidence=ConfidenceLevel.HIGH,
                            url=test_url,
                            payload=attack_payload,
                            evidence=f"Status: {response.status_code}, Length: {len(response.text)}",
                            remediation=f"Review access controls for {path}. Ensure sensitive files/directories are properly protected.",
                            cwe_id="CWE-200",
                            owasp_category="A01:2021 - Broken Access Control",
                        )

                # Rate limiting
                if context.config.delay_between_requests > 0:
                    await asyncio.sleep(context.config.delay_between_requests)

                return None

        # Process wordlist in batches to avoid overwhelming the server
        batch_size = 10
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i : i + batch_size]
            tasks = [test_path(path) for path in batch]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, VulnerabilityFinding):
                    vulnerabilities.append(result)
                elif isinstance(result, Exception):
                    self.logger.debug(f"Error in path enumeration: {result}")

        return vulnerabilities

    async def _enumerate_files(
        self, context: AttackContext, discovered_paths: set[str]
    ) -> list[VulnerabilityFinding]:
        """Enumerate common files in discovered directories."""
        vulnerabilities = []

        common_filenames = [
            "index",
            "default",
            "main",
            "home",
            "admin",
            "login",
            "test",
            "config",
            "backup",
            "db",
            "database",
            "readme",
            "changelog",
            "version",
            "info",
            "phpinfo",
            ".htaccess",
            "web.config",
        ]

        for dir_path in discovered_paths:
            if len(vulnerabilities) >= context.config.max_payloads:
                break

            for filename in common_filenames[:10]:  # Limit files per directory
                for ext in self.common_extensions[:5]:  # Limit extensions
                    test_filename = filename + ext
                    test_url = urljoin(dir_path, test_filename)

                    response = await self.send_request(context, test_url)
                    if response and response.status_code == 200:
                        attack_payload = self.create_payload_object(
                            test_filename, "file", "GET"
                        )

                        vuln = self.create_vulnerability(
                            title=f"Accessible file: {test_filename}",
                            description=f"File {test_filename} is accessible and may contain sensitive information.",
                            severity=self._get_file_severity(test_filename),
                            confidence=ConfidenceLevel.HIGH,
                            url=test_url,
                            payload=attack_payload,
                            evidence=f"File accessible with status 200, size: {len(response.text)} bytes",
                            remediation="Review file permissions and consider removing or protecting sensitive files.",
                            cwe_id="CWE-200",
                            owasp_category="A01:2021 - Broken Access Control",
                        )
                        vulnerabilities.append(vuln)

                    # Rate limiting
                    if context.config.delay_between_requests > 0:
                        await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_sensitive_files(
        self, context: AttackContext, base_url: str
    ) -> list[VulnerabilityFinding]:
        """Test for known sensitive files."""
        vulnerabilities = []

        for sensitive_path in self.sensitive_paths:
            test_url = urljoin(base_url, sensitive_path)

            response = await self.send_request(context, test_url)
            if response and response.status_code in [200, 301, 302, 403]:
                attack_payload = self.create_payload_object(
                    sensitive_path, "sensitive_file", "GET"
                )

                severity = (
                    Severity.HIGH if response.status_code == 200 else Severity.MEDIUM
                )

                vuln = self.create_vulnerability(
                    title=f"Sensitive path detected: {sensitive_path}",
                    description=f"Potentially sensitive path '{sensitive_path}' is accessible or exists on the server.",
                    severity=severity,
                    confidence=ConfidenceLevel.HIGH,
                    url=test_url,
                    payload=attack_payload,
                    evidence=f"Status: {response.status_code}",
                    remediation="Secure or remove sensitive files/directories from web-accessible locations.",
                    cwe_id="CWE-200",
                    owasp_category="A01:2021 - Broken Access Control",
                )
                vulnerabilities.append(vuln)

            # Rate limiting
            if context.config.delay_between_requests > 0:
                await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    def _analyze_response(
        self, status_code: int, path: str, response
    ) -> tuple[str | None, Severity, str]:
        """Analyze response to determine finding type and severity."""
        # Basic analysis based on status code
        status_map = {
            200: (
                "Directory/File Found",
                Severity.INFO,
                f"Path '{path}' is accessible and returned content.",
            ),
            301: (
                "Directory Found (Redirect)",
                Severity.INFO,
                f"Directory '{path}' exists (redirected).",
            ),
            302: (
                "Resource Found (Redirect)",
                Severity.INFO,
                f"Resource '{path}' exists (redirected).",
            ),
            403: (
                "Forbidden Directory",
                Severity.LOW,
                f"Directory '{path}' exists but access is forbidden.",
            ),
            401: (
                "Authentication Required",
                Severity.MEDIUM,
                f"Resource '{path}' requires authentication.",
            ),
        }

        return status_map.get(status_code, (None, Severity.INFO, ""))

    def _get_file_severity(self, filename: str) -> Severity:
        """Determine severity based on filename."""
        filename_lower = filename.lower()

        # High priority files
        if any(
            word in filename_lower
            for word in ["config", "backup", ".env", "database", "admin", "password"]
        ):
            return Severity.HIGH

        # Medium priority files
        if any(
            word in filename_lower
            for word in ["log", ".git", ".svn", "phpinfo", "info"]
        ):
            return Severity.MEDIUM

        # Default
        return Severity.LOW
