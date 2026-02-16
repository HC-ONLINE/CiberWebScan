"""
Analyze service for CiberWebScan.

Orchestrates security analysis operations using core analyzers.
Supports SSL, technology fingerprinting, and CVE analysis with optional export.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ciberwebscan.config.loader import get_config
from ciberwebscan.core.analyzers import (
    SecurityHeadersAnalyzer,
    SSLAnalysisResult,
    SSLAnalyzer,
    TechnologyFingerprinter,
)
from ciberwebscan.core.analyzers.cve import (
    CVEAggregator,
    CVESource,
)
from ciberwebscan.export.models import (
    AnalysisReport,
    ConfidenceLevel,
    CVEResult,
    ExportMeta,
    FingerprintResult,
    HeaderFinding,
    HeadersResult,
    Severity,
    SSLResult,
    TechnologyMatch,
)
from ciberwebscan.export.models import CVEReference as ExportCVEReference
from ciberwebscan.services.base import (
    BaseService,
    ExecutionError,
    ServiceResult,
    ValidationError,
)

logger = logging.getLogger(__name__)


@dataclass
class AnalyzeOptions:
    """Options for analysis operations."""

    # Target
    url: str

    # Analysis types
    ssl: bool = True
    fingerprint: bool = True
    cve: bool = True
    analyze_headers: bool = True

    # SSL options
    ssl_verify: bool = True
    ssl_timeout: float = 10.0

    # Fingerprint options
    deep_scan: bool = False

    # CVE options
    cve_sources: list[str] = field(default_factory=lambda: ["nvd"])
    cve_limit: int = 100
    cve_severity: str | None = None  # Filter by severity

    # Export
    export: str | None = None
    export_format: str = "json"

    # Advanced
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    user_agent: str | None = None
    timeout: float = 30.0
    check_robots: bool = False  # Not typically needed for analysis
    enrich_exploits: bool = False  # Enrich CVEs with exploit info


class AnalyzeService(BaseService):
    """
    Service for security analysis operations.

    Provides high-level interface for:
    - SSL/TLS certificate analysis
    - Technology fingerprinting
    - CVE vulnerability lookup
    - Combined security reports

    Example:
        service = AnalyzeService()
        result = service.analyze(AnalyzeOptions(
            url="https://example.com",
            ssl=True,
            fingerprint=True,
            cve=True,
            export="report.json"
        ))
        if result.success:
            report = result.data
            print(f"Found {len(report.fingerprint.technologies)} technologies")
    """

    def __init__(self):
        """Initialize analyze service."""
        super().__init__()
        self.app_config = get_config()
        self._ssl_analyzer: SSLAnalyzer | None = None
        self._fingerprinter: TechnologyFingerprinter | None = None
        self._cve_aggregator: CVEAggregator | None = None
        self._headers_analyzer: SecurityHeadersAnalyzer | None = None

        # Initialize user agent provider from config
        from ciberwebscan.core.client.user_agent import UserAgentProvider

        self._user_agent_provider = UserAgentProvider.from_config(
            self.app_config.user_agent
        )

        # Initialize proxy rotator from config
        self._proxy_rotator = self._build_proxy_rotator()

    def _build_proxy_rotator(self):
        """Build a ProxyRotator from config if proxy rotation is enabled."""
        from ciberwebscan.core.client.proxy import ProxyRotator

        proxy_cfg = self.app_config.http.proxy
        if proxy_cfg is None or not proxy_cfg.rotate:
            return None

        proxies: list[str] = []
        if proxy_cfg.proxy_list:
            proxies = list(proxy_cfg.proxy_list)
        else:
            for url in (proxy_cfg.http, proxy_cfg.https):
                if url is not None:
                    proxies.append(str(url))
            if proxy_cfg.socks5:
                proxies.append(proxy_cfg.socks5)

        if not proxies:
            logger.warning(
                "Proxy rotation enabled but no proxies configured — "
                "set proxy_list or individual proxy fields"
            )
            return None

        rotator = ProxyRotator(
            proxies=proxies,
            rotation_interval=proxy_cfg.rotation_interval,
        )
        logger.info(
            "Proxy rotation enabled: %d proxies, interval=%d",
            len(proxies),
            proxy_cfg.rotation_interval,
        )
        return rotator

    def _resolve_proxy(self, explicit_proxy: str | None) -> str | None:
        """Return *explicit_proxy* when provided, otherwise ask the rotator."""
        if explicit_proxy:
            return explicit_proxy
        if self._proxy_rotator:
            return self._proxy_rotator.next()
        return None

    @property
    def ssl_analyzer(self) -> SSLAnalyzer:
        """Get or create SSL analyzer instance."""
        if self._ssl_analyzer is None:
            ssl_cfg = self.app_config.analysis.ssl
            self._ssl_analyzer = SSLAnalyzer(
                check_expiry=ssl_cfg.check_expiry,
                check_chain=ssl_cfg.check_chain,
                check_revocation=ssl_cfg.check_revocation,
                warning_days=ssl_cfg.warning_days,
            )
        return self._ssl_analyzer

    @property
    def fingerprinter(self) -> TechnologyFingerprinter:
        """Get or create fingerprinter instance."""
        if self._fingerprinter is None:
            fp_cfg = self.app_config.analysis.fingerprint
            self._fingerprinter = TechnologyFingerprinter(
                check_headers=fp_cfg.check_headers,
                check_html=fp_cfg.check_html,
                check_scripts=fp_cfg.check_scripts,
                check_cookies=fp_cfg.check_cookies,
                check_dns=fp_cfg.check_dns,
            )
        return self._fingerprinter

    @property
    def cve_aggregator(self) -> CVEAggregator:
        """Get or create CVE aggregator instance."""
        if self._cve_aggregator is None:
            cve_cfg = self.app_config.analysis.cve
            sources = self._resolve_cve_sources(cve_cfg.api)
            self._cve_aggregator = CVEAggregator(
                sources=sources,
                nvd_api_key=cve_cfg.nvd_api_key or "",
                vulners_api_key=cve_cfg.vulners_api_key or "",
                cache_ttl=cve_cfg.cache_ttl,
            )
        return self._cve_aggregator

    @property
    def headers_analyzer(self) -> SecurityHeadersAnalyzer:
        """Get or create security headers analyzer instance."""
        if self._headers_analyzer is None:
            hdr_cfg = self.app_config.analysis.headers
            self._headers_analyzer = SecurityHeadersAnalyzer(
                required_headers=hdr_cfg.required_headers,
            )
        return self._headers_analyzer

    @staticmethod
    def _resolve_cve_sources(api: str) -> list[CVESource]:
        """Convert the ``analysis.cve.api`` config value to a source list."""
        source_map: dict[str, list[CVESource]] = {
            "nvd": [CVESource.NVD],
            "circl": [CVESource.CIRCL],
            "vulners": [CVESource.VULNERS],
            "all": [CVESource.NVD, CVESource.CIRCL, CVESource.VULNERS],
        }
        return source_map.get(api, [CVESource.NVD, CVESource.CIRCL])

    def analyze(self, options: AnalyzeOptions) -> ServiceResult[AnalysisReport]:
        """
        Perform a security analysis.

        Args:
            options: Analysis options.

        Returns:
            ServiceResult containing analysis report.
        """
        result = ServiceResult[AnalysisReport](success=False)

        try:
            # Validate URL
            url = self._validate_url(options.url)
            self.logger.info(f"Analyzing: {url}")

            # Initialize report with meta
            meta = ExportMeta(target_url=url)
            report = AnalysisReport(
                meta=meta,
                ssl=None,
                fingerprint=None,
                headers=None,
                cves=[],
            )

            # SSL Analysis (respect both config enabled flag and CLI option)
            ssl_enabled = self.app_config.analysis.ssl.enabled and options.ssl
            if ssl_enabled:
                ssl_result = self._analyze_ssl(url, options)
                report.ssl = ssl_result

            # Technology Fingerprinting
            fp_enabled = (
                self.app_config.analysis.fingerprint.enabled and options.fingerprint
            )
            if fp_enabled:
                fingerprint_result = self._fingerprint(url, options)
                report.fingerprint = fingerprint_result

            # Headers Analysis
            headers_enabled = (
                self.app_config.analysis.headers.enabled and options.analyze_headers
            )
            if headers_enabled:
                headers_result = self._analyze_headers(url, options)
                report.headers = headers_result

            # CVE Lookup
            cve_enabled = self.app_config.analysis.cve.enabled and options.cve
            if cve_enabled and report.fingerprint and report.fingerprint.technologies:
                cve_results = self._lookup_cves(
                    report.fingerprint.technologies, options
                )
                report.cves = cve_results

            result.data = report
            result.success = True

            # Handle export
            if options.export:
                exported, path = self._export_result(
                    report,
                    options.export,
                    options.export_format,
                )
                result.exported = exported
                result.export_path = path
                result.export_format = options.export_format

        except ValidationError as e:
            result.error = str(e)
            result.error_code = e.code
            self.logger.error(f"Validation error: {e}")
        except ExecutionError as e:
            result.error = str(e)
            result.error_code = e.code
            self.logger.error(f"Execution error: {e}")
        except Exception as e:
            result.error = str(e)
            result.error_code = "UNEXPECTED_ERROR"
            self.logger.exception(f"Unexpected error during analysis: {e}")

        return result.finalize()

    def analyze_ssl(self, url: str, **kwargs: Any) -> ServiceResult[SSLResult]:
        """
        Perform SSL-only analysis.

        Args:
            url: URL to analyze.
            **kwargs: Additional options.

        Returns:
            ServiceResult containing SSL analysis.
        """
        result = ServiceResult[SSLResult](success=False)

        try:
            url = self._validate_url(url)
            ssl_result = self._analyze_ssl(
                url,
                AnalyzeOptions(url=url, **kwargs),
            )
            result.data = ssl_result
            result.success = True

        except Exception as e:
            result.error = str(e)
            result.error_code = "SSL_ANALYSIS_ERROR"

        return result.finalize()

    def fingerprint_url(
        self,
        url: str,
        deep: bool = False,
        **kwargs: Any,
    ) -> ServiceResult[FingerprintResult]:
        """
        Perform technology fingerprinting.

        Args:
            url: URL to fingerprint.
            deep: Enable deep scanning.
            **kwargs: Additional options.

        Returns:
            ServiceResult containing detected technologies.
        """
        result = ServiceResult[FingerprintResult](success=False)

        try:
            url = self._validate_url(url)
            fingerprint_result = self._fingerprint(
                url,
                AnalyzeOptions(url=url, deep_scan=deep, **kwargs),
            )
            result.data = fingerprint_result
            result.success = True

        except Exception as e:
            result.error = str(e)
            result.error_code = "FINGERPRINT_ERROR"

        return result.finalize()

    def lookup_cves(
        self,
        technologies: Sequence[TechnologyMatch | str],
        **kwargs: Any,
    ) -> ServiceResult[list[CVEResult]]:
        """
        Lookup CVEs for technologies.

        Args:
            technologies: List of technologies to check.
            **kwargs: Additional options.

        Returns:
            ServiceResult containing CVE results.
        """
        result = ServiceResult[list[CVEResult]](success=False)

        try:
            # Normalize technologies to TechnologyMatch instances
            tech_list: list[TechnologyMatch] = []
            for t in technologies:
                if isinstance(t, TechnologyMatch):
                    tech_list.append(t)
                else:
                    tech_list.append(TechnologyMatch(name=str(t)))

            cve_results = self._lookup_cves(
                tech_list,
                AnalyzeOptions(url="", **kwargs),
            )
            result.data = cve_results
            result.success = True

        except Exception as e:
            result.error = str(e)
            result.error_code = "CVE_LOOKUP_ERROR"

        return result.finalize()

    def _analyze_ssl(
        self,
        url: str,
        options: AnalyzeOptions,
    ) -> SSLResult | None:
        """Internal SSL analysis."""
        try:
            ssl_timeout = (
                self.app_config.http.timeout.connect
                if options.ssl_timeout == 10.0
                else options.ssl_timeout
            )
            ssl_cfg = self.app_config.analysis.ssl
            analyzer = SSLAnalyzer(
                timeout=int(ssl_timeout),
                check_expiry=ssl_cfg.check_expiry,
                check_chain=ssl_cfg.check_chain,
                check_revocation=ssl_cfg.check_revocation,
                warning_days=ssl_cfg.warning_days,
            )
            ssl_info: SSLAnalysisResult = analyzer.analyze(url)

            # Convert internal SSLAnalysisResult to export SSLResult
            return SSLResult(
                is_https=ssl_info.ssl_enabled,
                protocol_version=(
                    (ssl_info.protocols.preferred_cipher or "")
                    if ssl_info.protocols
                    else ""
                ),
                cipher_suite=(
                    (
                        ssl_info.protocols.cipher_suites[0]
                        if ssl_info.protocols.cipher_suites
                        else ""
                    )
                    if ssl_info.protocols
                    else ""
                ),
                certificate=None,  # Would need to convert certificate info
                chain_valid=(
                    (not ssl_info.certificate.is_self_signed)
                    if ssl_info.certificate
                    else None
                ),
                findings=[],
                grade=(
                    ssl_info.security_assessment.overall_grade
                    if ssl_info.security_assessment
                    else None
                ),
            )

        except Exception as e:
            self.logger.warning(f"SSL analysis failed: {e}")
            return None

    def _analyze_headers(
        self,
        url: str,
        options: AnalyzeOptions,
    ) -> HeadersResult | None:
        """Internal security headers analysis."""
        try:
            from ciberwebscan.core.client.http_client import HTTPClient

            timeout = (
                self.app_config.http.timeout.read
                if options.timeout == 30.0
                else options.timeout
            )
            default_headers = dict(options.headers or {})
            if options.user_agent:
                default_headers["User-Agent"] = options.user_agent
            else:
                default_headers["User-Agent"] = self._user_agent_provider.get()

            with HTTPClient(
                timeout=timeout,
                default_headers=default_headers or None,
                proxy=self._resolve_proxy(options.proxy),
            ) as client:
                resp = client.get(url, cookies=options.cookies or None)

            response_headers = dict(resp.headers)
            analysis = self.headers_analyzer.analyze(response_headers)

            findings: list[HeaderFinding] = []
            for header_name in analysis.get("missing_required", []):
                findings.append(
                    HeaderFinding(
                        header=header_name,
                        present=False,
                        severity=Severity.MEDIUM,
                        recommendation=f"Add the {header_name} header",
                    )
                )

            # Calculate a simple score based on individual header scores
            header_keys = [
                "csp",
                "hsts",
                "frame_options",
                "content_type_nosniff",
                "xss_protection",
                "referrer_policy",
                "permissions_policy",
            ]
            scores = [
                analysis[k].get("score", 0)
                for k in header_keys
                if k in analysis and isinstance(analysis[k], dict)
            ]
            overall_score = int(sum(scores) / len(scores)) if scores else 0

            return HeadersResult(
                findings=findings,
                score=overall_score,
            )

        except Exception as e:
            self.logger.warning(f"Headers analysis failed: {e}")
            return None

    def _fingerprint(
        self,
        url: str,
        options: AnalyzeOptions,
    ) -> FingerprintResult | None:
        """Internal technology fingerprinting."""
        try:
            # Fetch page to obtain headers and HTML for fingerprinting
            from ciberwebscan.core.client.http_client import HTTPClient

            timeout = (
                self.app_config.http.timeout.read
                if options.timeout == 30.0
                else options.timeout
            )
            default_headers = dict(options.headers or {})
            if options.user_agent:
                default_headers["User-Agent"] = options.user_agent
            else:
                # Use configured user agent
                default_headers["User-Agent"] = self._user_agent_provider.get()

            with HTTPClient(
                timeout=timeout,
                default_headers=default_headers or None,
                proxy=self._resolve_proxy(options.proxy),
            ) as client:
                resp = client.get(url, cookies=options.cookies or None)
            headers = dict(resp.headers)
            html = resp.text

            fp_result = self.fingerprinter.fingerprint(headers, html)

            # Convert to FingerprintResult model
            technologies: list[TechnologyMatch] = []
            techs = fp_result.get("technologies", {})
            for category, items in techs.items():
                for item in items:
                    if isinstance(item, dict):
                        name = item.get("name") or ""
                        version = item.get("version")
                        confidence = item.get("confidence")
                    else:
                        name = str(item)
                        version = None
                        confidence = None

                    technologies.append(
                        TechnologyMatch(
                            name=name,
                            version=version,
                            category=category,
                            confidence=(
                                ConfidenceLevel.MEDIUM
                                if confidence is None
                                else confidence
                            ),
                        )
                    )

            return FingerprintResult(
                technologies=technologies,
                server=fp_result.get("server"),
                powered_by=fp_result.get("powered_by"),
                framework=fp_result.get("framework"),
                cms=fp_result.get("cms"),
                cdn=fp_result.get("cdn"),
                waf=fp_result.get("waf"),
            )

        except Exception as e:
            self.logger.warning(f"Fingerprinting failed: {e}")
            return None

    def _lookup_cves(
        self,
        technologies: list[TechnologyMatch],
        options: AnalyzeOptions,
    ) -> list[CVEResult]:
        """Internal CVE lookup."""
        try:
            all_cves: list[CVEResult] = []

            for tech in technologies:
                # Search CVEs for this technology
                aggregated = self.cve_aggregator.search(
                    product=tech.name,
                    limit=options.cve_limit,
                )

                for cve in aggregated.entries:
                    # Filter by severity if specified
                    if options.cve_severity and (
                        str(cve.severity.value).lower() != options.cve_severity.lower()
                    ):
                        continue

                    all_cves.append(
                        CVEResult(
                            id=cve.id,
                            source=cve.source.value if cve.source else "unknown",
                            title=cve.title,
                            description=cve.description,
                            severity=(
                                Severity(cve.severity.value)
                                if hasattr(cve, "severity")
                                and cve.severity
                                and cve.severity.value
                                in {"critical", "high", "medium", "low"}
                                else Severity.INFO
                            ),
                            cvss=None,
                            cwe_ids=cve.cwe_ids,
                            affected_products=[
                                f"{p.vendor}/{p.product}@{p.version_exact or ''}"
                                for p in cve.affected_products
                            ],
                            references=[
                                ExportCVEReference(url=r.url) for r in cve.references
                            ],
                            published_date=cve.published_date,
                            last_modified=(
                                cve.last_modified_date
                                if hasattr(cve, "last_modified_date")
                                else None
                            ),
                            exploitability_score=(
                                cve.cvss.exploitability_score if cve.cvss else None
                            ),
                            impact_score=(cve.cvss.impact_score if cve.cvss else None),
                            raw_data=(
                                cve.raw_data if hasattr(cve, "raw_data") else None
                            ),
                        )
                    )

            return all_cves

        except Exception as e:
            self.logger.warning(f"CVE lookup failed: {e}")
            return []
