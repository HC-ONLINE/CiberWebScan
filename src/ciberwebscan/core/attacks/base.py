"""
Base classes and utilities for attack simulation modules.

Provides common functionality shared across different attack types.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from unittest.mock import Mock

import httpx
from bs4 import BeautifulSoup

from ciberwebscan.core.client import HTTPClient
from ciberwebscan.export.models import (
    AttackPayload,
    ConfidenceLevel,
    Severity,
    VulnerabilityFinding,
)

logger = logging.getLogger(__name__)


class AttackIntensity(str, Enum):
    """Attack intensity levels."""

    LOW = "low"  # Conservative testing, minimal payloads
    MEDIUM = "medium"  # Balanced approach, moderate payload set
    HIGH = "high"  # Aggressive testing, comprehensive payloads


@dataclass
class AttackConfig:
    """Configuration for attack operations."""

    # Target and scope
    target_url: str
    scope_urls: list[str] = field(default_factory=list)

    # Attack settings
    intensity: AttackIntensity = AttackIntensity.MEDIUM
    max_payloads: int = 50
    timeout: float = 10.0

    # Rate limiting
    delay_between_requests: float = 0.1
    concurrent_requests: int = 1

    # Custom payloads
    custom_payloads_file: str | None = None

    # POST/JSON body template (each key is tested one at a time)
    json_body: dict[str, Any] | None = None

    # User consent and safety
    user_consent: bool = False
    skip_dangerous_payloads: bool = True

    # Output
    verbose: bool = False


@dataclass
class AttackContext:
    """Runtime context for an attack session."""

    config: AttackConfig
    http_client: HTTPClient
    start_time: float = field(default_factory=time.time)

    # Statistics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0

    # Results
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)

    def elapsed_time(self) -> float:
        """Get elapsed time since attack started."""
        return time.time() - self.start_time

    def add_vulnerability(self, vuln: VulnerabilityFinding) -> None:
        """Add a vulnerability finding."""
        self.vulnerabilities.append(vuln)
        if self.config.verbose:
            logger.info(f"Vulnerability found: {vuln.type} - {vuln.title}")

    def log_request(self, success: bool) -> None:
        """Log a request attempt."""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1


class AttackEngine(ABC):
    """Base class for all attack modules."""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")

    @abstractmethod
    async def execute(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute the attack and return findings."""
        pass

    @abstractmethod
    def get_payloads(self, intensity: AttackIntensity, max_count: int) -> list[str]:
        """Get payloads for this attack type."""
        pass

    def validate_target(self, url: str) -> bool:
        """Validate if target is appropriate for this attack."""
        return url.startswith(("http://", "https://"))

    def create_payload_object(
        self, payload_str: str, parameter: str = "", method: str = "GET"
    ) -> AttackPayload:
        """Create an AttackPayload object."""
        return AttackPayload(
            type=self.name, payload=payload_str, parameter=parameter, method=method
        )

    def create_vulnerability(
        self,
        title: str,
        description: str,
        severity: Severity,
        confidence: ConfidenceLevel,
        url: str,
        payload: AttackPayload,
        evidence: str = "",
        remediation: str = "",
        cwe_id: str | None = None,
        owasp_category: str | None = None,
    ) -> VulnerabilityFinding:
        """Create a VulnerabilityFinding object."""
        return VulnerabilityFinding(
            type=self.name,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            url=url,
            payload=payload,
            evidence=evidence,
            remediation=remediation,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
        )

    async def send_request(
        self,
        context: AttackContext,
        url: str,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response | None:
        """Send HTTP request with error handling.

        The underlying `HTTPClient` is synchronous; run its methods in a thread
        via `asyncio.to_thread` so this coroutine does not block the event loop.
        For mocked clients in tests, call directly to avoid threading issues.
        Passing *json_body* sends the body as a JSON POST request.
        """
        try:
            if isinstance(context.http_client, Mock):
                # For testing with mocked clients, call directly
                if method.upper() == "GET":
                    response = context.http_client.get(url, params=params or {})
                elif json_body is not None:
                    response = context.http_client.post(
                        url, json=json_body, params=params or {}
                    )
                elif method.upper() == "POST":
                    response = context.http_client.post(
                        url, data=data or {}, params=params or {}
                    )
                else:
                    response = context.http_client.request(
                        method, url, data=data, params=params
                    )
            else:
                # Use thread for real HTTPClient
                if method.upper() == "GET":
                    response = await asyncio.to_thread(
                        context.http_client.get, url, params=params
                    )
                elif json_body is not None:
                    response = await asyncio.to_thread(
                        context.http_client.post,
                        url,
                        json=json_body,
                        params=params,
                    )
                elif method.upper() == "POST":
                    response = await asyncio.to_thread(
                        context.http_client.post,
                        url,
                        data=data or {},
                        params=params,
                    )
                else:
                    response = await asyncio.to_thread(
                        context.http_client.request,
                        method,
                        url,
                        data=data,
                        params=params,
                    )

            context.log_request(True)
            return response

        except Exception as e:
            context.log_request(False)
            self.logger.debug(f"Request failed to {url}: {e}")
            return None

    def extract_forms(self, html: str) -> list[dict[str, Any]]:
        """Extract forms from HTML response.

        Uses the canonical extractor from core.scraping.extractor and normalizes
        the output to use the 'inputs' key for backward compatibility with
        attack modules (xss, sqli, csrf, traversal).
        """
        try:
            from ciberwebscan.core.scraping.extractor import (
                extract_forms as _extract_forms,
            )

            soup = BeautifulSoup(html, "html.parser")
            raw_forms = _extract_forms(soup)
            # Normalize: 'fields' → 'inputs' for attack module compatibility
            for form in raw_forms:
                form["inputs"] = form.pop("fields", [])
            return raw_forms

        except Exception as e:
            self.logger.debug(f"Error extracting forms: {e}")
            return []

    def should_test_parameter(self, param_name: str) -> bool:
        """Check if parameter should be tested based on name."""
        # Skip obvious non-user-input parameters
        skip_params = {
            "csrf_token",
            "authenticity_token",
            "_token",
            "__viewstate",
            "sessionid",
            "session_id",
            "_session",
            "timestamp",
        }
        return param_name.lower() not in skip_params
