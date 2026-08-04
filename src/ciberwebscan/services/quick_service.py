"""
Quick scan service for CiberWebScan.

Orchestrates analysis + attacks + scraping in a single operation using presets.
Presets (low/medium/high) define which services run and their configuration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ciberwebscan.export.models import AnalysisReport, ExportMeta
from ciberwebscan.services.analyze_service import AnalyzeOptions, AnalyzeService
from ciberwebscan.services.attack_service import AttackOptions, AttackService
from ciberwebscan.services.base import BaseService, ServiceResult, ValidationError
from ciberwebscan.services.scrape_service import ScrapeOptions, ScrapeService

logger = logging.getLogger(__name__)

PRESETS: dict[str, dict[str, Any]] = {
    "low": {
        "analyze": {
            "ssl": True,
            "fingerprint": True,
            "cve": False,
            "analyze_headers": True,
            "cve_limit": 0,
            "timeout": 10.0,
        },
        "attack": None,
        "scrape": {"dynamic": False},
    },
    "medium": {
        "analyze": {
            "ssl": True,
            "fingerprint": True,
            "cve": True,
            "analyze_headers": True,
            "cve_limit": 100,
            "timeout": 30.0,
        },
        "attack": {
            "xss": True,
            "sqli": True,
            "traversal": False,
            "enumeration": False,
            "intensity": "medium",
            "max_payloads": 50,
        },
        "scrape": {"dynamic": False},
    },
    "high": {
        "analyze": {
            "ssl": True,
            "fingerprint": True,
            "cve": True,
            "analyze_headers": True,
            "cve_limit": 500,
            "enrich_exploits": True,
            "timeout": 60.0,
        },
        "attack": {
            "xss": True,
            "sqli": True,
            "traversal": True,
            "enumeration": True,
            "subdomain": True,
            "intensity": "high",
            "max_payloads": 200,
        },
        "scrape": {"dynamic": True},
    },
}


@dataclass
class QuickOptions:
    """Options for quick scan operations."""

    url: str
    preset: str = "low"

    # Network
    timeout: float | None = None
    proxy: str | None = None
    user_agent: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    # Attack
    consent: bool = False

    # Scrape
    selector: str | None = None
    dynamic: bool = False

    # Export
    output: str | None = None
    export_format: str = "json"

    # Output
    json_output: bool = False
    quiet: bool = False
    verbose: bool = False


class QuickService(BaseService):
    """
    Service for combined quick scan operations.

    Orchestrates AnalyzeService -> AttackService -> ScrapeService
    based on preset configuration, combining results into a single report.
    """

    def __init__(self):
        super().__init__()
        self._analyze_service: AnalyzeService | None = None
        self._attack_service: AttackService | None = None
        self._scrape_service: ScrapeService | None = None

    @property
    def analyze_service(self) -> AnalyzeService:
        if self._analyze_service is None:
            self._analyze_service = AnalyzeService()
        return self._analyze_service

    @property
    def attack_service(self) -> AttackService:
        if self._attack_service is None:
            self._attack_service = AttackService()
        return self._attack_service

    @property
    def scrape_service(self) -> ScrapeService:
        if self._scrape_service is None:
            self._scrape_service = ScrapeService()
        return self._scrape_service

    def quick_scan(self, options: QuickOptions) -> ServiceResult[AnalysisReport]:
        """
        Perform a quick scan combining analysis, attacks, and scraping.

        Args:
            options: Quick scan options.

        Returns:
            ServiceResult containing the combined AnalysisReport.
        """
        result = ServiceResult[AnalysisReport](success=False)

        try:
            # Validate URL
            url = self._validate_url(options.url)

            # Validate preset
            preset = options.preset.lower()
            if preset not in PRESETS:
                raise ValidationError(
                    f"Invalid preset: {preset}. Must be: low, medium, high"
                )

            preset_config = PRESETS[preset]

            # Validate consent for medium/high
            if preset in ("medium", "high") and not options.consent:
                raise ValidationError(
                    f"User consent is required for '{preset}' preset. "
                    "Use --consent flag to confirm you have permission to test this system."
                )

            self.logger.info(f"Quick scan: {url} (preset={preset})")

            # Initialize report
            meta = ExportMeta(target_url=url)
            report = AnalysisReport(meta=meta)

            # Step 1: Analysis (always runs)
            self._run_analysis(url, options, preset_config, report)

            # Step 2: Attacks (medium/high only)
            if preset_config["attack"] is not None:
                self._run_attacks(url, options, preset_config, report)

            # Step 3: Scraping (when selector or dynamic is provided)
            if options.selector or (
                options.dynamic and preset_config["scrape"]["dynamic"]
            ):
                self._run_scrape(url, options, preset_config, report)

            # Calculate summary
            report.calculate_summary()

            result.data = report
            result.success = True

            # Export if requested
            if options.output:
                exported, path = self._export_result(
                    report,
                    options.output,
                    options.export_format,
                )
                result.exported = exported
                result.export_path = path
                result.export_format = options.export_format

        except ValidationError:
            raise
        except Exception as e:
            result.error = str(e)
            result.error_code = "QUICK_SCAN_ERROR"
            self.logger.exception(f"Quick scan failed: {e}")

        return result.finalize()

    def _run_analysis(
        self,
        url: str,
        options: QuickOptions,
        preset_config: dict[str, Any],
        report: AnalysisReport,
    ) -> None:
        """Run analysis phase."""
        analyze_cfg = preset_config["analyze"]

        analyze_options = AnalyzeOptions(
            url=url,
            ssl=analyze_cfg["ssl"],
            fingerprint=analyze_cfg["fingerprint"],
            cve=analyze_cfg["cve"],
            analyze_headers=analyze_cfg["analyze_headers"],
            cve_limit=analyze_cfg.get("cve_limit", 100),
            enrich_exploits=analyze_cfg.get("enrich_exploits", False),
            timeout=options.timeout or analyze_cfg["timeout"],
            headers=dict(options.headers),
            cookies=dict(options.cookies),
            proxy=options.proxy,
            user_agent=options.user_agent,
        )

        self.logger.info("Running analysis...")
        analyze_result = self.analyze_service.analyze(analyze_options)

        if analyze_result.success and analyze_result.data:
            report.ssl = analyze_result.data.ssl
            report.fingerprint = analyze_result.data.fingerprint
            report.headers = analyze_result.data.headers
            report.cves = analyze_result.data.cves
        else:
            self.logger.warning(f"Analysis failed: {analyze_result.error}")

    def _run_attacks(
        self,
        url: str,
        options: QuickOptions,
        preset_config: dict[str, Any],
        report: AnalysisReport,
    ) -> None:
        """Run attack simulation phase."""
        attack_cfg = preset_config["attack"]

        attack_options = AttackOptions(
            url=url,
            user_consent=options.consent,
            xss=attack_cfg["xss"],
            sqli=attack_cfg["sqli"],
            traversal=attack_cfg["traversal"],
            enumeration=attack_cfg["enumeration"],
            subdomain=attack_cfg.get("subdomain", False),
            intensity=attack_cfg["intensity"],
            max_payloads=attack_cfg["max_payloads"],
            timeout=options.timeout or 10.0,
            headers=dict(options.headers),
            cookies=dict(options.cookies),
            proxy=options.proxy,
            user_agent=options.user_agent,
            verbose=options.verbose,
        )

        self.logger.info("Running attack simulation...")
        attack_result = self.attack_service.attack(attack_options)

        if attack_result.success and attack_result.data:
            report.attack = attack_result.data
        else:
            self.logger.warning(f"Attacks failed: {attack_result.error}")

    def _run_scrape(
        self,
        url: str,
        options: QuickOptions,
        preset_config: dict[str, Any],
        report: AnalysisReport,
    ) -> None:
        """Run scraping phase."""
        scrape_cfg = preset_config["scrape"]

        scrape_options = ScrapeOptions(
            url=url,
            dynamic=options.dynamic and scrape_cfg.get("dynamic", False),
            selector=options.selector,
            timeout=options.timeout or 30.0,
            headers=dict(options.headers),
            cookies=dict(options.cookies),
            proxy=options.proxy,
            user_agent=options.user_agent,
        )

        self.logger.info("Running scrape...")
        scrape_result = self.scrape_service.scrape(scrape_options)

        if scrape_result.success and scrape_result.data:
            data = scrape_result.data
            if isinstance(data, list):
                report.scrape = None
            else:
                report.scrape = data
        else:
            self.logger.warning(f"Scrape failed: {scrape_result.error}")
