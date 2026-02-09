"""
SQL Injection vulnerability detection.

Detects SQL injection vulnerabilities through payload injection
and response analysis for error messages and behavioral changes.
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


class SQLiAttacker(AttackEngine):
    """SQL Injection vulnerability detection engine."""

    def __init__(self):
        super().__init__("sqli")
        self.payload_loader = PayloadLoader()

        # SQL error patterns for different databases
        self.error_patterns = [
            # MySQL
            re.compile(r"MySQL.*syntax.*error", re.IGNORECASE),
            re.compile(r"mysql_fetch_row\(\)", re.IGNORECASE),
            re.compile(r"Unknown column.*in 'field list'", re.IGNORECASE),
            re.compile(r"Table.*doesn't exist", re.IGNORECASE),
            # PostgreSQL
            re.compile(r"PSQLException", re.IGNORECASE),
            re.compile(r"unterminated quoted string", re.IGNORECASE),
            re.compile(r"column.*does not exist", re.IGNORECASE),
            # SQL Server
            re.compile(r"Microsoft.*ODBC.*SQL Server.*Driver", re.IGNORECASE),
            re.compile(r"SQLServer JDBC Driver", re.IGNORECASE),
            re.compile(r"Invalid column name", re.IGNORECASE),
            re.compile(r"Unclosed quotation mark", re.IGNORECASE),
            # Oracle
            re.compile(r"ORA-\d{5}", re.IGNORECASE),
            re.compile(r"Oracle.*Driver", re.IGNORECASE),
            re.compile(r"quoted string not properly terminated", re.IGNORECASE),
            # SQLite
            re.compile(r"SQLite.*syntax error", re.IGNORECASE),
            re.compile(r"no such column", re.IGNORECASE),
            # Generic SQL errors
            re.compile(r"SQL syntax.*error", re.IGNORECASE),
            re.compile(r"syntax error.*query", re.IGNORECASE),
            re.compile(r"unexpected end of SQL command", re.IGNORECASE),
        ]

    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Get SQL injection payloads based on intensity level."""
        return self.payload_loader.get_payloads("sqli", intensity, max_count)

    async def execute(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute SQL injection attack simulation."""
        self.logger.info(f"Starting SQLi testing on {context.config.target_url}")

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

        # Test SQL injection in URL parameters
        param_vulns = await self._test_url_parameters(
            context, response, original_text, original_length, original_status
        )
        vulnerabilities.extend(param_vulns)

        # Test SQL injection in forms
        form_vulns = await self._test_form_sqli(
            context, response, original_text, original_length, original_status
        )
        vulnerabilities.extend(form_vulns)

        self.logger.info(
            f"SQLi testing completed. Found {len(vulnerabilities)} vulnerabilities"
        )
        return vulnerabilities

    async def _test_url_parameters(
        self,
        context: AttackContext,
        response,
        original_text: str,
        original_length: int,
        original_status: int,
    ) -> list[VulnerabilityFinding]:
        """Test URL parameters for SQL injection."""
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

            for payload in payloads[:8]:  # Limit payloads per parameter
                vuln = await self._test_parameter_sqli(
                    context,
                    response.url,
                    param_name,
                    payload,
                    "GET",
                    original_text,
                    original_length,
                    original_status,
                )
                if vuln:
                    vulnerabilities.append(vuln)

                # Rate limiting
                if context.config.delay_between_requests > 0:
                    await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_form_sqli(
        self,
        context: AttackContext,
        response,
        original_text: str,
        original_length: int,
        original_status: int,
    ) -> list[VulnerabilityFinding]:
        """Test form inputs for SQL injection."""
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

                for payload in payloads[:5]:  # Limit payloads per field
                    vuln = await self._test_parameter_sqli(
                        context,
                        action_url,
                        field_name,
                        payload,
                        form["method"],
                        original_text,
                        original_length,
                        original_status,
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                    # Rate limiting
                    if context.config.delay_between_requests > 0:
                        await asyncio.sleep(context.config.delay_between_requests)

        return vulnerabilities

    async def _test_parameter_sqli(
        self,
        context: AttackContext,
        url: str,
        param_name: str,
        payload: str,
        method: str,
        original_text: str,
        original_length: int,
        original_status: int,
    ) -> VulnerabilityFinding | None:
        """Test a specific parameter for SQL injection."""
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

            # Analyze response for SQL injection indicators
            confidence, evidence = self._analyze_sqli_response(
                test_response.text,
                test_response.status_code,
                len(test_response.text),
                original_text,
                original_length,
                original_status,
                payload,
            )

            if confidence != ConfidenceLevel.LOW or evidence:
                attack_payload = self.create_payload_object(payload, param_name, method)

                return self.create_vulnerability(
                    title=f"Potential SQL Injection in parameter '{param_name}'",
                    description=f"Parameter '{param_name}' appears vulnerable to SQL injection attacks. Database errors or response changes detected when malicious SQL was injected.",
                    severity=self._get_sqli_severity(confidence),
                    confidence=confidence,
                    url=str(test_response.url),
                    payload=attack_payload,
                    evidence=evidence,
                    remediation="Use parameterized queries/prepared statements. Implement proper input validation and escape user inputs.",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 - Injection",
                )

        except Exception as e:
            self.logger.debug(f"Error testing SQLi in parameter {param_name}: {e}")

        return None

    def _analyze_sqli_response(
        self,
        response_text: str,
        status_code: int,
        response_length: int,
        original_text: str,
        original_length: int,
        original_status: int,
        payload: str,
    ) -> tuple[ConfidenceLevel, str]:
        """Analyze response for SQL injection indicators."""
        evidence_parts = []

        # Check for SQL error messages (high confidence)
        for pattern in self.error_patterns:
            if pattern.search(response_text):
                evidence_parts.append(f"SQL error detected: {pattern.pattern[:50]}...")
                return ConfidenceLevel.HIGH, "; ".join(evidence_parts)

        # Check for significant response changes
        length_diff = abs(response_length - original_length)

        # Status code changed
        if status_code != original_status:
            if status_code == 500:  # Internal server error
                evidence_parts.append(
                    f"Status changed from {original_status} to {status_code} (Internal Server Error)"
                )
                return ConfidenceLevel.MEDIUM, "; ".join(evidence_parts)
            else:
                evidence_parts.append(
                    f"Status changed from {original_status} to {status_code}"
                )

        # Significant length change (could indicate different query results)
        if length_diff > original_length * 0.1:  # More than 10% change
            evidence_parts.append(
                f"Response length changed significantly ({original_length} -> {response_length})"
            )

        # Check for specific SQL injection success indicators
        success_indicators = [
            r"mysql_num_rows",
            r"Warning.*mysql_fetch",
            r"Microsoft.*ODBC.*Error",
            r"Oracle.*Driver",
            r"PostgreSQL.*ERROR",
        ]

        for indicator in success_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                evidence_parts.append(f"Database-specific output detected: {indicator}")
                return ConfidenceLevel.MEDIUM, "; ".join(evidence_parts)

        # Return low confidence if we have some evidence
        if evidence_parts:
            return ConfidenceLevel.LOW, "; ".join(evidence_parts)

        return ConfidenceLevel.LOW, ""

    def _get_sqli_severity(self, confidence: ConfidenceLevel) -> Severity:
        """Determine SQL injection severity based on confidence level."""
        if confidence == ConfidenceLevel.HIGH:
            return Severity.CRITICAL  # SQL injection is always critical
        elif confidence == ConfidenceLevel.MEDIUM:
            return Severity.HIGH
        else:
            return Severity.MEDIUM
