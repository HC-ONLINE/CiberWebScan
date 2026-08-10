"""
OS Command Injection vulnerability detection.

Detects command injection vulnerabilities through payload injection into
URL parameters, HTML form fields, and JSON request bodies, then analyzes
responses for unique echo markers, OS error messages, and timing behavior.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
from urllib.parse import parse_qs, urljoin, urlparse

from ciberwebscan.export.models import (
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)

from .base import AttackContext, AttackEngine, AttackIntensity
from .payloads import PayloadLoader

logger = logging.getLogger(__name__)


class CommandInjectionAttacker(AttackEngine):
    """OS command injection vulnerability detection engine."""

    MARKER_PREFIX = "cmdi"
    MARKER_PAYLOAD_TEMPLATES = [
        ";echo {marker}",
        "|echo {marker}",
        "&echo {marker}&",
        "`echo {marker}`",
        "$(echo {marker})",
        "%0aecho {marker}%0a",
    ]

    def __init__(self):
        super().__init__("command_injection")
        self.payload_loader = PayloadLoader()

        # OS command error patterns for different systems
        self.error_patterns = [
            # Linux/Unix shells
            re.compile(r"/bin/sh:\s*\d+:", re.IGNORECASE),
            re.compile(r"\bsh:\s*\d+:", re.IGNORECASE),
            re.compile(r"\bbash:\s*[^:]+:", re.IGNORECASE),
            re.compile(r"command not found", re.IGNORECASE),
            re.compile(r"Permission denied", re.IGNORECASE),
            re.compile(r"No such file or directory", re.IGNORECASE),
            re.compile(r"syntax error: unexpected", re.IGNORECASE),
            re.compile(r"unexpected EOF while looking for matching", re.IGNORECASE),
            # Windows cmd
            re.compile(
                r"is not recognized as an internal or external command",
                re.IGNORECASE,
            ),
            re.compile(r"not recognized as an internal or external", re.IGNORECASE),
            re.compile(r"Access is denied", re.IGNORECASE),
            # Python/Node runtime traces
            re.compile(r"OSError: \[Errno 2\]", re.IGNORECASE),
            re.compile(r"subprocess\.CalledProcessError", re.IGNORECASE),
            re.compile(r"Error: spawn .* ENOENT", re.IGNORECASE),
        ]

    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Get command injection payloads based on intensity level."""
        return self.payload_loader.get_payloads(
            "command_injection", intensity, max_count
        )

    async def execute(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute command injection attack simulation."""
        self.logger.info(
            f"Starting Command Injection testing on {context.config.target_url}"
        )

        vulnerabilities = []

        # Get target response to analyze
        response = await self.send_request(context, context.config.target_url)
        if not response:
            self.logger.warning("Could not fetch target URL")
            return vulnerabilities

        # Store original response for comparison
        original_text = response.text
        original_status = response.status_code
        original_length = len(original_text)
        baseline_elapsed = self._response_elapsed(response)

        # Test command injection in URL parameters (GET)
        param_vulns = await self._test_url_parameters(
            context,
            response,
            original_text,
            original_length,
            original_status,
            baseline_elapsed,
        )
        vulnerabilities.extend(param_vulns)

        # Test command injection in form fields (POST)
        form_vulns = await self._test_form_injection(
            context,
            response,
            original_text,
            original_length,
            original_status,
            baseline_elapsed,
        )
        vulnerabilities.extend(form_vulns)

        # Test command injection in JSON request body (POST)
        json_vulns = await self._test_json_body(
            context,
            response,
            original_text,
            original_length,
            original_status,
            baseline_elapsed,
        )
        vulnerabilities.extend(json_vulns)

        self.logger.info(
            "Command Injection testing completed. "
            f"Found {len(vulnerabilities)} vulnerabilities"
        )
        return vulnerabilities

    def _build_marker_payloads(self, marker: str) -> list[str]:
        """Build payloads that echo a unique marker when executed."""
        return [
            template.format(marker=marker) for template in self.MARKER_PAYLOAD_TEMPLATES
        ]

    def _new_marker(self) -> str:
        """Generate a unique marker for echo-based detection."""
        return f"{self.MARKER_PREFIX}{secrets.token_hex(5)}"

    @staticmethod
    def _extract_markers(payload: str) -> list[str]:
        """Extract unique echo markers embedded in a payload."""
        return re.findall(r"cmdi[0-9a-f]{10}", payload)

    async def _test_url_parameters(
        self,
        context: AttackContext,
        response,
        original_text: str,
        original_length: int,
        original_status: int,
        baseline_elapsed: float,
    ) -> list[VulnerabilityFinding]:
        """Test URL query parameters for command injection (GET)."""
        vulnerabilities = []
        parsed_url = urlparse(str(response.url))

        if not parsed_url.query:
            return vulnerabilities

        query_params = parse_qs(parsed_url.query)
        payloads = self.get_payloads(
            context.config.intensity, context.config.max_payloads
        )

        for param_name, _param_values in query_params.items():
            if not self.should_test_parameter(param_name):
                continue

            # Echo-marker probes first, then static payloads
            marker = self._new_marker()
            probes = self._build_marker_payloads(marker) + payloads[:8]

            for payload in probes:
                vuln = await self._test_parameter_cmdi(
                    context,
                    str(response.url),
                    param_name,
                    payload,
                    "GET",
                    original_text,
                    original_length,
                    original_status,
                    baseline_elapsed,
                )
                if vuln:
                    vulnerabilities.append(vuln)

                # Rate limiting
                if context.config.delay_between_requests > 0:
                    await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_form_injection(
        self,
        context: AttackContext,
        response,
        original_text: str,
        original_length: int,
        original_status: int,
        baseline_elapsed: float,
    ) -> list[VulnerabilityFinding]:
        """Test POST form inputs for command injection."""
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
            method = form.get("method", "post") or "post"

            for input_field in form["inputs"]:
                if input_field["type"].lower() in [
                    "hidden",
                    "submit",
                    "button",
                    "file",
                ]:
                    continue

                field_name = input_field["name"]
                if not field_name or not self.should_test_parameter(field_name):
                    continue

                marker = self._new_marker()
                probes = self._build_marker_payloads(marker) + payloads[:5]

                for payload in probes:
                    vuln = await self._test_parameter_cmdi(
                        context,
                        action_url,
                        field_name,
                        payload,
                        method,
                        original_text,
                        original_length,
                        original_status,
                        baseline_elapsed,
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                    # Rate limiting
                    if context.config.delay_between_requests > 0:
                        await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_json_body(
        self,
        context: AttackContext,
        response,
        original_text: str,
        original_length: int,
        original_status: int,
        baseline_elapsed: float,
    ) -> list[VulnerabilityFinding]:
        """Test a configured POST/JSON body for command injection."""
        vulnerabilities = []

        json_body = context.config.json_body
        if not json_body:
            return vulnerabilities

        payloads = self.get_payloads(
            context.config.intensity, min(context.config.max_payloads, 8)
        )
        target_url = str(response.url)

        for param_name, _param_value in json_body.items():
            if not self.should_test_parameter(param_name):
                continue

            marker = self._new_marker()
            probes = self._build_marker_payloads(marker) + payloads[:8]

            for payload in probes:
                body = self._splice_json_body(json_body, param_name, payload)
                vuln = await self._test_parameter_cmdi(
                    context,
                    target_url,
                    param_name,
                    payload,
                    "POST",
                    original_text,
                    original_length,
                    original_status,
                    baseline_elapsed,
                    json_body=body,
                )
                if vuln:
                    vulnerabilities.append(vuln)

                # Rate limiting
                if context.config.delay_between_requests > 0:
                    await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    @staticmethod
    def _splice_json_body(
        body: dict[str, object], key: str, value: object
    ) -> dict[str, object]:
        """Return a copy of *body* with only *key* replaced by *value*."""
        return {k: (value if k == key else v) for k, v in body.items()}

    async def _test_parameter_cmdi(
        self,
        context: AttackContext,
        url: str,
        param_name: str,
        payload: str,
        method: str,
        original_text: str,
        original_length: int,
        original_status: int,
        baseline_elapsed: float,
        json_body: dict[str, object] | None = None,
    ) -> VulnerabilityFinding | None:
        """Test a specific parameter for command injection."""
        try:
            if method.upper() == "GET":
                test_response = await self.send_request(
                    context, url, "GET", params={param_name: payload}
                )
            elif json_body is not None:
                test_response = await self.send_request(
                    context, url, "POST", json_body=json_body
                )
            else:
                test_response = await self.send_request(
                    context, url, "POST", data={param_name: payload}
                )

            if not test_response:
                return None

            # Analyze response for command injection indicators
            confidence, evidence = self._analyze_cmdi_response(
                test_response.text,
                test_response.status_code,
                len(test_response.text),
                original_text,
                original_length,
                original_status,
                baseline_elapsed,
                self._response_elapsed(test_response),
                payload,
            )

            if confidence != ConfidenceLevel.LOW or evidence:
                payload_method = "POST" if method.upper() != "GET" else "GET"
                attack_payload = self.create_payload_object(
                    payload, param_name, payload_method
                )

                return self.create_vulnerability(
                    title=(
                        f"Potential OS Command Injection in parameter '{param_name}'"
                    ),
                    description=(
                        f"Parameter '{param_name}' appears vulnerable to OS command "
                        "injection. System error messages, unique echo markers, or "
                        "timing differences were detected when command payloads "
                        "were injected."
                    ),
                    severity=self._get_cmdi_severity(confidence),
                    confidence=confidence,
                    url=str(test_response.url),
                    payload=attack_payload,
                    evidence=evidence,
                    remediation=(
                        "Avoid invoking OS commands with user input. If required, "
                        "use allowlisted arguments or libraries that prevent shell "
                        "interpretation, and validate/sanitize all inputs."
                    ),
                    cwe_id="CWE-78",
                    owasp_category="A03:2021 - Injection",
                )

        except Exception as e:
            self.logger.debug(f"Error testing command injection in {param_name}: {e}")

        return None

    def _analyze_cmdi_response(
        self,
        response_text: str,
        status_code: int,
        response_length: int,
        original_text: str,
        original_length: int,
        original_status: int,
        baseline_elapsed: float,
        response_elapsed: float,
        payload: str,
    ) -> tuple[ConfidenceLevel, str]:
        """Analyze response for command injection indicators."""
        evidence_parts = []

        # Check for echoed unique marker (high confidence)
        for marker in self._extract_markers(payload):
            if marker and marker in response_text:
                evidence_parts.append(
                    f"Unique echo marker '{marker}' reflected in response"
                )
                return ConfidenceLevel.HIGH, "; ".join(evidence_parts)

        # Check for OS command error messages
        for pattern in self.error_patterns:
            if pattern.search(response_text):
                evidence_parts.append(
                    f"OS command error detected: {pattern.pattern[:50]}..."
                )
                return ConfidenceLevel.HIGH, "; ".join(evidence_parts)

        # Check for time-based injection indicators
        if baseline_elapsed > 0:
            delay = response_elapsed - baseline_elapsed
            if delay >= 4.0:
                evidence_parts.append(
                    f"Response delay detected ({baseline_elapsed:.2f}s -> "
                    f"{response_elapsed:.2f}s), consistent with time-based injection"
                )
                return ConfidenceLevel.HIGH, "; ".join(evidence_parts)
            if delay >= 2.0:
                evidence_parts.append(
                    f"Notable response delay detected "
                    f"({baseline_elapsed:.2f}s -> {response_elapsed:.2f}s)"
                )
                return ConfidenceLevel.MEDIUM, "; ".join(evidence_parts)

        # Check for significant response changes
        length_diff = abs(response_length - original_length)

        # Status code changed
        if status_code != original_status:
            if status_code == 500:  # Internal server error
                evidence_parts.append(
                    f"Status changed from {original_status} to {status_code} "
                    "(Internal Server Error)"
                )
                return ConfidenceLevel.MEDIUM, "; ".join(evidence_parts)
            evidence_parts.append(
                f"Status changed from {original_status} to {status_code}"
            )

        # Significant length change (could indicate command output)
        if length_diff > original_length * 0.1:  # More than 10% change
            evidence_parts.append(
                f"Response length changed significantly "
                f"({original_length} -> {response_length})"
            )

        # Return low confidence if we have some evidence
        if evidence_parts:
            return ConfidenceLevel.LOW, "; ".join(evidence_parts)

        return ConfidenceLevel.LOW, ""

    @staticmethod
    def _response_elapsed(response) -> float:
        """Extract elapsed seconds from a response, defaulting to 0.0."""
        try:
            elapsed = getattr(response, "elapsed", None)
            if elapsed is None:
                return 0.0
            total_seconds = elapsed.total_seconds()
            return total_seconds if total_seconds is not None else 0.0
        except Exception:
            return 0.0

    def _get_cmdi_severity(self, confidence: ConfidenceLevel) -> Severity:
        """Determine command injection severity based on confidence level."""
        if confidence == ConfidenceLevel.HIGH:
            return Severity.CRITICAL  # Command injection is always critical
        elif confidence == ConfidenceLevel.MEDIUM:
            return Severity.HIGH
        else:
            return Severity.MEDIUM
