"""
Cross-Site Request Forgery (CSRF) vulnerability detection.

Detects forms that modify state (POST, PUT, DELETE) without CSRF token
protection, which could allow attackers to forge requests on behalf
of authenticated users.
"""

from __future__ import annotations

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

# Known CSRF token field names (lowercase for comparison)
CSRF_TOKEN_NAMES: set[str] = {
    "csrf",
    "_csrf",
    "csrf_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "_token",
    "__requestverificationtoken",
    "xsrf",
    "_xsrf",
    "xsrf-token",
    "antiforgery",
    "__viewstate",
    "__viewstatevalidation",
    "token",
    "csrftoken",
    "_csrf_token",
    "csrf_protection",
    "formtoken",
    "form_token",
    "verificationtoken",
    "anticsrf",
    "anti-csrf",
}

# Sensitive field names that increase severity when combined with missing CSRF
SENSITIVE_FIELD_NAMES: set[str] = {
    "password",
    "passwd",
    "pass",
    "email",
    "amount",
    "transfer",
    "delete",
    "remove",
    "admin",
    "role",
    "permission",
    "payment",
    "credit_card",
    "card_number",
    "ssn",
    "phone",
    "address",
    "user",
    "username",
    "action",
    "confirm",
}


class CSRFAttacker(AttackEngine):
    """CSRF vulnerability detection engine.

    Unlike XSS/SQLi, CSRF detection is a **static analysis** of forms.
    It does not inject payloads; instead it inspects whether POST forms
    include a hidden field whose name matches known CSRF token patterns.
    """

    def __init__(self) -> None:
        super().__init__("csrf")
        self.payload_loader = PayloadLoader()

    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Return known CSRF token names (used as reference, not injection)."""
        return self.payload_loader.get_payloads("csrf", intensity, max_count)

    async def execute(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute CSRF analysis on the target URL."""
        self.logger.info(f"Starting CSRF analysis on {context.config.target_url}")

        vulnerabilities: list[VulnerabilityFinding] = []

        response = await self.send_request(context, context.config.target_url)
        if not response:
            self.logger.warning("Could not fetch target URL for CSRF analysis")
            return vulnerabilities

        forms = self.extract_forms(response.text)
        self.logger.debug(f"Extracted {len(forms)} forms from target page")

        for form in forms:
            finding = self._analyze_form(form, str(response.url))
            if finding:
                vulnerabilities.append(finding)

        self.logger.info(
            f"CSRF analysis completed. Found {len(vulnerabilities)} vulnerabilities"
        )
        return vulnerabilities

    def _analyze_form(
        self, form: dict[str, object], page_url: str
    ) -> VulnerabilityFinding | None:
        """Analyze a single form for CSRF protection.

        Returns a VulnerabilityFinding if the form is a state-modifying
        POST form without a CSRF token, otherwise None.
        """
        method = str(form.get("method", "GET"))
        if method != "POST":
            return None

        inputs_raw = form.get("inputs", [])
        if not inputs_raw or not isinstance(inputs_raw, list):
            return None

        inputs: list[dict[str, str]] = [
            item for item in inputs_raw if isinstance(item, dict)
        ]
        if not inputs:
            return None

        has_csrf_token = False
        for input_field in inputs:
            name = str(input_field.get("name", "")).lower()
            input_type = str(input_field.get("type", "text")).lower()
            if input_type == "hidden" and name in CSRF_TOKEN_NAMES:
                has_csrf_token = True
                break

        if has_csrf_token:
            return None

        action = str(form.get("action", ""))
        action_url = urljoin(page_url, action) if action else page_url
        field_names = [str(f.get("name", "")) for f in inputs if f.get("name")]

        severity = self._determine_severity(inputs)
        confidence = ConfidenceLevel.HIGH

        attack_payload = self.create_payload_object(
            payload_str="NO_CSRF_TOKEN",
            parameter=",".join(field_names[:5]),
            method="POST",
        )

        return self.create_vulnerability(
            title="Formulario POST sin token CSRF",
            description=(
                "El formulario que envia datos via POST no contiene un campo "
                "oculto con token CSRF conocido. Esto permite que un atacante "
                "forgie peticiones en nombre de usuarios autenticados."
            ),
            severity=severity,
            confidence=confidence,
            url=action_url,
            payload=attack_payload,
            evidence=(
                f"Campos del formulario: {', '.join(field_names[:10])}. "
                f"Ninguno coincide con patrones de token CSRF conocidos."
            ),
            remediation=(
                "Implementar tokens CSRF en todos los formularios que "
                "realizan cambios de estado. Usar frameworks que proporcionen "
                "proteccion CSRF automatica (Django CSRF middleware, Rails "
                "authenticity_token, Spring Security CSRF, etc.)."
            ),
            cwe_id="CWE-352",
            owasp_category="A01:2021 - Broken Access Control",
        )

    def _determine_severity(self, inputs: list[dict[str, str]]) -> Severity:
        """Determine severity based on form field names.

        Forms with sensitive fields (password, payment, delete) get HIGH;
        other state-modifying POST forms get MEDIUM.
        """
        for input_field in inputs:
            name = str(input_field.get("name", "")).lower()
            if any(sensitive in name for sensitive in SENSITIVE_FIELD_NAMES):
                return Severity.HIGH
        return Severity.MEDIUM
