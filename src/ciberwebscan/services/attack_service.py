"""
Attack service for CiberWebScan.

Orchestrates security attack simulations using core attack modules.
Supports XSS, SQL injection, path traversal, and directory enumeration testing
with optional export.

WARNING: Only use against systems you own or have explicit written permission
to test. Unauthorized security testing is illegal and unethical.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ciberwebscan.config.loader import get_config
from ciberwebscan.core.attacks import (
    AttackConfig,
    AttackContext,
    DirectoryEnumerator,
    PathTraversalAttacker,
    SQLiAttacker,
    XSSAttacker,
)
from ciberwebscan.core.attacks.base import AttackIntensity
from ciberwebscan.core.client import HTTPClient
from ciberwebscan.export.models import (
    AttackResult,
    ExportMeta,
    VulnerabilityFinding,
)
from ciberwebscan.services.base import (
    BaseService,
    ExecutionError,
    ServiceResult,
    ValidationError,
)

logger = logging.getLogger(__name__)


@dataclass
class AttackOptions:
    """Options for attack simulation operations."""

    # Target
    url: str
    user_consent: bool = False  # MUST be True to execute attacks

    # Attack types to run
    xss: bool = False
    sqli: bool = False
    traversal: bool = False
    enumeration: bool = False

    # Attack configuration
    intensity: str = "medium"  # low, medium, high
    max_payloads: int = 50
    timeout: float = 10.0
    delay_between_requests: float = 0.1
    concurrent_requests: int = 1

    # Custom payloads
    custom_payloads_file: str | None = None
    custom_wordlist: str | None = None  # For enumeration

    # Safety settings
    skip_dangerous_payloads: bool = True
    scope_urls: list[str] = field(default_factory=list)

    # Export
    export: str | None = None
    export_format: str = "json"

    # Advanced
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    user_agent: str | None = None
    verbose: bool = False


class AttackService(BaseService):
    """
    Service for security attack simulation operations.

    Provides high-level interface for:
    - Cross-Site Scripting (XSS) testing
    - SQL Injection testing
    - Path Traversal testing
    - Directory/File enumeration

    Example:
        service = AttackService()
        result = service.attack(AttackOptions(
            url="https://example.com",
            user_consent=True,
            xss=True,
            sqli=True,
            intensity="medium",
            export="attack_report.json"
        ))
        if result.success:
            report = result.data
            print(f"Found {report.total_findings} vulnerabilities")
    """

    def __init__(self):
        """Initialize attack service."""
        super().__init__()
        self.app_config = get_config()

        # Initialize user agent provider from config
        from ciberwebscan.core.client.user_agent import UserAgentProvider

        self._user_agent_provider = UserAgentProvider.from_config(
            self.app_config.user_agent
        )

    def attack(self, options: AttackOptions) -> ServiceResult[AttackResult]:
        """
        Perform security attack simulations.

        Args:
            options: Attack options.

        Returns:
            ServiceResult containing attack report.

        Raises:
            ValidationError: If user consent not provided or options invalid.
            ExecutionError: If attack execution fails.
        """
        result = ServiceResult[AttackResult](success=False)

        try:
            # CRITICAL: Verify user consent
            if not options.user_consent:
                raise ValidationError(
                    "User consent is required to perform attack simulations. "
                    "Set user_consent=True only if you own the target system "
                    "or have explicit written permission to test it.",
                    details={"url": options.url},
                )

            # Validate at least one attack type selected
            if not any(
                [options.xss, options.sqli, options.traversal, options.enumeration]
            ):
                raise ValidationError(
                    "At least one attack type must be enabled (xss, sqli, traversal, enumeration)",
                    details={"url": options.url},
                )

            # Validate URL
            url = self._validate_url(options.url)
            self.logger.warning(f"[ATTACK MODE] Starting security testing on: {url}")
            self.logger.warning("Ensure you have permission to test this system!")

            # Validate intensity
            try:
                intensity = AttackIntensity(options.intensity.lower())
            except ValueError:
                raise ValidationError(
                    f"Invalid intensity: {options.intensity}. Must be: low, medium, high",
                    details={"url": url},
                ) from None

            # Build attack configuration
            attack_config = AttackConfig(
                target_url=url,
                scope_urls=options.scope_urls or [url],
                intensity=intensity,
                max_payloads=options.max_payloads,
                timeout=options.timeout,
                delay_between_requests=options.delay_between_requests,
                concurrent_requests=options.concurrent_requests,
                custom_payloads_file=options.custom_payloads_file,
                user_consent=True,  # Already validated
                skip_dangerous_payloads=options.skip_dangerous_payloads,
                verbose=options.verbose,
            )

            # Prepare default headers (including user agent if provided)
            default_headers = dict(options.headers or {})
            if options.user_agent:
                default_headers["User-Agent"] = options.user_agent
            else:
                # Use configured user agent
                default_headers["User-Agent"] = self._user_agent_provider.get()

            http_config = self.app_config.http
            timeout = (
                http_config.timeout.connect
                if options.timeout == 10.0
                else options.timeout
            )

            # Create HTTP client
            http_client = HTTPClient(
                timeout=timeout,
                max_retries=http_config.retry.max_attempts,
                backoff_factor=http_config.retry.backoff_factor,
                rate_limit=(
                    http_config.rate_limit.requests_per_second
                    if http_config.rate_limit.per_domain
                    else None
                ),
                http2=http_config.http2,
                verify=http_config.verify_ssl,
                follow_redirects=http_config.follow_redirects,
                default_headers=default_headers or None,
                proxy=options.proxy,
            )

            # Create attack context
            context = AttackContext(config=attack_config, http_client=http_client)

            # Execute attacks
            all_vulnerabilities: list[VulnerabilityFinding] = []

            if options.xss:
                self.logger.info("Running XSS attack simulation...")
                xss_vulns = self._execute_xss_attack(context)
                all_vulnerabilities.extend(xss_vulns)
                self.logger.info(
                    f"XSS: Found {len(xss_vulns)} potential vulnerabilities"
                )

            if options.sqli:
                self.logger.info("Running SQL Injection attack simulation...")
                sqli_vulns = self._execute_sqli_attack(context)
                all_vulnerabilities.extend(sqli_vulns)
                self.logger.info(
                    f"SQLi: Found {len(sqli_vulns)} potential vulnerabilities"
                )

            if options.traversal:
                self.logger.info("Running Path Traversal attack simulation...")
                traversal_vulns = self._execute_traversal_attack(context)
                all_vulnerabilities.extend(traversal_vulns)
                self.logger.info(
                    f"Path Traversal: Found {len(traversal_vulns)} potential vulnerabilities"
                )

            if options.enumeration:
                self.logger.info("Running Directory Enumeration...")
                enum_vulns = self._execute_enumeration_attack(
                    context, options.custom_wordlist
                )
                all_vulnerabilities.extend(enum_vulns)
                self.logger.info(
                    f"Enumeration: Found {len(enum_vulns)} interesting resources"
                )

            # Create attack result
            attack_result = AttackResult(
                target_url=url,
                vulnerabilities=all_vulnerabilities,
                total_payloads_tested=context.total_requests,
                total_findings=len(all_vulnerabilities),
                xss_findings=sum(1 for v in all_vulnerabilities if v.type == "xss"),
                sqli_findings=sum(1 for v in all_vulnerabilities if v.type == "sqli"),
                traversal_findings=sum(
                    1 for v in all_vulnerabilities if v.type == "traversal"
                ),
                enumeration_findings=sum(
                    1 for v in all_vulnerabilities if v.type == "enumeration"
                ),
                duration_seconds=context.elapsed_time(),
            )

            # Export if requested
            if options.export:
                self._export_attack_result(attack_result, options, result)

            result.data = attack_result
            result.success = True

            self.logger.info(
                f"Attack simulation completed: {len(all_vulnerabilities)} findings "
                f"({context.total_requests} requests in {context.elapsed_time():.2f}s)"
            )

        except ValidationError:
            raise
        except ExecutionError:
            raise
        except Exception as e:
            self.logger.exception("Unexpected error during attack simulation")
            raise ExecutionError(
                f"Attack simulation failed: {e}",
                details={"url": options.url, "error_type": type(e).__name__},
            ) from e

        return result.finalize()

    def _execute_xss_attack(self, context: AttackContext) -> list[VulnerabilityFinding]:
        """Execute XSS attack simulation."""
        import asyncio

        attacker = XSSAttacker()

        try:
            # Run async attack in sync context
            vulnerabilities = asyncio.run(attacker.execute(context))
            return vulnerabilities
        except Exception as e:
            self.logger.error(f"XSS attack failed: {e}")
            return []

    def _execute_sqli_attack(
        self, context: AttackContext
    ) -> list[VulnerabilityFinding]:
        """Execute SQL Injection attack simulation."""
        import asyncio

        attacker = SQLiAttacker()

        try:
            vulnerabilities = asyncio.run(attacker.execute(context))
            return vulnerabilities
        except Exception as e:
            self.logger.error(f"SQLi attack failed: {e}")
            return []

    def _execute_traversal_attack(
        self, context: AttackContext
    ) -> list[VulnerabilityFinding]:
        """Execute Path Traversal attack simulation."""
        import asyncio

        attacker = PathTraversalAttacker()

        try:
            vulnerabilities = asyncio.run(attacker.execute(context))
            return vulnerabilities
        except Exception as e:
            self.logger.error(f"Path Traversal attack failed: {e}")
            return []

    def _execute_enumeration_attack(
        self, context: AttackContext, custom_wordlist: str | None = None
    ) -> list[VulnerabilityFinding]:
        """Execute Directory Enumeration attack simulation."""
        import asyncio

        enumerator = DirectoryEnumerator()

        try:
            # If custom wordlist provided, could load it here
            # For now, using default payloads
            vulnerabilities = asyncio.run(enumerator.execute(context))
            return vulnerabilities
        except Exception as e:
            self.logger.error(f"Directory enumeration failed: {e}")
            return []

    def _export_attack_result(
        self,
        attack_result: AttackResult,
        options: AttackOptions,
        result: ServiceResult[AttackResult],
    ) -> None:
        """Export attack results to file."""
        try:
            from ciberwebscan.export.models import AnalysisReport

            # Create metadata
            meta = ExportMeta(
                target_url=options.url,
                duration_seconds=attack_result.duration_seconds,
                total_requests=attack_result.total_payloads_tested,
            )

            # Create full report with findings
            full_report = AnalysisReport(
                meta=meta,
                attack=attack_result,
            )
            full_report.calculate_summary()

            # Export using BaseService method
            if options.export:
                exported, final_path = self._export_result(
                    data=full_report,
                    output_path=options.export,
                    format=options.export_format,
                )

            result.exported = exported
            result.export_path = final_path
            result.export_format = options.export_format

            if exported:
                self.logger.info(f"Attack results exported to: {final_path}")

        except Exception as e:
            self.logger.warning(f"Export failed: {e}")
            result.warnings.append(f"Export failed: {e}")
