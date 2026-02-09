"""
Cross-Site Scripting (XSS) vulnerability detection.

Detects reflected, stored, and DOM-based XSS vulnerabilities through
controlled payload injection and response analysis.
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import parse_qs, urljoin, urlparse

from ciberwebscan.export.models import (
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)

from .base import AttackContext, AttackEngine, AttackIntensity
from .payloads import PayloadLoader

logger = logging.getLogger(__name__)


class XSSAttacker(AttackEngine):
    """XSS vulnerability detection engine."""

    def __init__(self):
        super().__init__("xss")
        self.payload_loader = PayloadLoader()

        # XSS detection patterns
        self.reflection_patterns = [
            re.compile(
                r"<script[^>]*>.*?alert\([^)]*\).*?</script>", re.IGNORECASE | re.DOTALL
            ),
            re.compile(r"alert\([^)]*\)", re.IGNORECASE),
            re.compile(r'javascript:[^"\'>\s]*alert\([^)]*\)', re.IGNORECASE),
            re.compile(r'on\w+=["\']?[^"\'>]*alert\([^)]*\)', re.IGNORECASE),
            re.compile(r"<img[^>]*onerror[^>]*alert\([^)]*\)", re.IGNORECASE),
        ]

        # DOM patterns for potential DOM XSS
        self.dom_patterns = [
            re.compile(r"document\.write\s*\(", re.IGNORECASE),
            re.compile(r"innerHTML\s*=", re.IGNORECASE),
            re.compile(r"outerHTML\s*=", re.IGNORECASE),
            re.compile(r"location\.href\s*=", re.IGNORECASE),
            re.compile(r"eval\s*\(", re.IGNORECASE),
        ]

    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Get XSS payloads based on intensity level."""
        return self.payload_loader.get_payloads("xss", intensity, max_count)

    async def execute(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute XSS attack simulation."""
        self.logger.info(f"Starting XSS testing on {context.config.target_url}")

        vulnerabilities = []

        # Get target response to analyze
        response = await self.send_request(context, context.config.target_url)
        if not response:
            self.logger.warning("Could not fetch target URL")
            return vulnerabilities

        # Test reflected XSS in URL parameters
        reflected_vulns = await self._test_reflected_xss(context, response)
        vulnerabilities.extend(reflected_vulns)

        # Test XSS in forms
        form_vulns = await self._test_form_xss(context, response)
        vulnerabilities.extend(form_vulns)

        # Analyze for DOM XSS potential
        dom_vulns = await self._analyze_dom_xss(context, response)
        vulnerabilities.extend(dom_vulns)

        self.logger.info(
            f"XSS testing completed. Found {len(vulnerabilities)} vulnerabilities"
        )
        return vulnerabilities

    async def _test_reflected_xss(
        self, context: AttackContext, response
    ) -> list[VulnerabilityFinding]:
        """Test for reflected XSS in URL parameters."""
        vulnerabilities = []
        parsed_url = urlparse(response.url)

        if not parsed_url.query:
            return vulnerabilities

        query_params = parse_qs(parsed_url.query)
        payloads = self.get_payloads(
            context.config.intensity, context.config.max_payloads
        )

        for param_name, _param_values in query_params.items():
            if not self.should_test_parameter(param_name):
                continue

            for payload in payloads[:10]:  # Limit payloads per parameter
                vuln = await self._test_parameter_xss(
                    context, response.url, param_name, payload, "GET"
                )
                if vuln:
                    vulnerabilities.append(vuln)

                # Rate limiting
                if context.config.delay_between_requests > 0:
                    await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_form_xss(
        self, context: AttackContext, response
    ) -> list[VulnerabilityFinding]:
        """Test for XSS in form inputs."""
        vulnerabilities = []

        forms = self.extract_forms(response.text)
        payloads = self.get_payloads(
            context.config.intensity, min(context.config.max_payloads, 5)
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
                if not field_name or not self.should_test_parameter(field_name):
                    continue

                for payload in payloads[:5]:  # Limit payloads per field
                    vuln = await self._test_parameter_xss(
                        context, action_url, field_name, payload, form["method"]
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                    # Rate limiting
                    if context.config.delay_between_requests > 0:
                        await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_parameter_xss(
        self,
        context: AttackContext,
        url: str,
        param_name: str,
        payload: str,
        method: str,
    ) -> VulnerabilityFinding | None:
        """Test a specific parameter for XSS vulnerability."""
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

            # Check if payload is reflected in response
            response_text = test_response.text.lower()
            payload_lower = payload.lower()

            # Simple reflection check
            if payload_lower in response_text:
                # Check for dangerous patterns
                confidence = self._analyze_xss_context(test_response.text, payload)

                if confidence != ConfidenceLevel.LOW:
                    attack_payload = self.create_payload_object(
                        payload, param_name, method
                    )

                    return self.create_vulnerability(
                        title=f"Potential XSS in parameter '{param_name}'",
                        description=f"User input in parameter '{param_name}' is reflected in the response without proper sanitization, potentially allowing XSS attacks.",
                        severity=self._get_xss_severity(confidence),
                        confidence=confidence,
                        url=str(test_response.url),
                        payload=attack_payload,
                        evidence=f"Payload '{payload}' reflected in response",
                        remediation="Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                    )

        except Exception as e:
            self.logger.debug(f"Error testing XSS in parameter {param_name}: {e}")

        return None

    async def _analyze_dom_xss(
        self, context: AttackContext, response
    ) -> list[VulnerabilityFinding]:
        """Analyze response for potential DOM XSS vulnerabilities."""
        vulnerabilities = []

        try:
            # Look for dangerous JavaScript patterns
            for pattern in self.dom_patterns:
                matches = pattern.findall(response.text)
                if matches:
                    attack_payload = self.create_payload_object(
                        "DOM_XSS_ANALYSIS", "", "STATIC"
                    )

                    vuln = self.create_vulnerability(
                        title="Potential DOM XSS vulnerability",
                        description=f"JavaScript code contains potentially dangerous patterns that could lead to DOM-based XSS: {', '.join(matches[:3])}",
                        severity=Severity.MEDIUM,
                        confidence=ConfidenceLevel.LOW,
                        url=str(response.url),
                        payload=attack_payload,
                        evidence=f"Found patterns: {', '.join(matches[:5])}",
                        remediation="Review JavaScript code for unsafe DOM manipulation. Validate and sanitize all user inputs before DOM operations.",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                    )
                    vulnerabilities.append(vuln)
                    break  # Only report once per page

        except Exception as e:
            self.logger.debug(f"Error in DOM XSS analysis: {e}")

        return vulnerabilities

    def _analyze_xss_context(self, response_text: str, payload: str) -> ConfidenceLevel:
        """Analyze the context of payload reflection to determine confidence."""
        # Check if payload appears in dangerous contexts
        for pattern in self.reflection_patterns:
            if pattern.search(response_text):
                return ConfidenceLevel.HIGH

        # Check if payload is in script tags, event handlers, etc.
        dangerous_contexts = [
            f"<script[^>]*>{re.escape(payload)}",
            f"on\\w+=[\"']?[^\"'>]*{re.escape(payload)}",
            f"javascript:[^\"'>\\s]*{re.escape(payload)}",
        ]

        for context_pattern in dangerous_contexts:
            if re.search(context_pattern, response_text, re.IGNORECASE):
                return ConfidenceLevel.MEDIUM

        # Basic reflection without dangerous context
        if payload.lower() in response_text.lower():
            return ConfidenceLevel.LOW

        return ConfidenceLevel.LOW

    def _get_xss_severity(self, confidence: ConfidenceLevel) -> Severity:
        """Determine XSS severity based on confidence level."""
        if confidence == ConfidenceLevel.HIGH:
            return Severity.HIGH
        elif confidence == ConfidenceLevel.MEDIUM:
            return Severity.MEDIUM
        else:
            return Severity.LOW
