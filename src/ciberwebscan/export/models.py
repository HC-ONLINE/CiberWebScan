"""
Export data models for CiberWebScan.

These models define the structure for all exportable data: scrape results,
analysis reports, CVE findings, and attack simulation results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# =============================================================================
# Common Types
# =============================================================================


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    """Confidence level for detections."""

    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# =============================================================================
# Metadata
# =============================================================================


class ExportMeta(BaseModel):
    """Metadata included in every export."""

    version: str = Field(default="2.0.0", description="CiberWebScan version")
    timestamp: datetime = Field(default_factory=_utc_now)
    target_url: str
    duration_seconds: float = 0.0
    total_requests: int = 0
    config_snapshot: dict[str, Any] | None = None


# =============================================================================
# Scraping Results
# =============================================================================


class LinkInfo(BaseModel):
    """Information about an extracted link."""

    href: str
    text: str = ""
    rel: list[str] = Field(default_factory=list)
    is_external: bool = False
    is_resource: bool = False


class ImageInfo(BaseModel):
    """Information about an extracted image."""

    src: str
    alt: str = ""
    width: int | None = None
    height: int | None = None


class FormInfo(BaseModel):
    """Information about an extracted form."""

    action: str = ""
    method: str = "GET"
    name: str = ""
    fields: list[dict[str, str]] = Field(default_factory=list)


class ScriptInfo(BaseModel):
    """Information about an extracted script."""

    src: str | None = None
    type: str = "text/javascript"
    is_inline: bool = False
    hash: str | None = Field(None, description="SHA256 of inline script content")


class ScrapeResult(BaseModel):
    """Result of a scraping operation."""

    url: str
    status_code: int
    content_type: str = ""
    title: str = ""
    meta_description: str = ""
    text_content: str = ""
    links: list[LinkInfo] = Field(default_factory=list)
    images: list[ImageInfo] = Field(default_factory=list)
    forms: list[FormInfo] = Field(default_factory=list)
    scripts: list[ScriptInfo] = Field(default_factory=list)
    raw_html: str | None = Field(None, description="Only if include_raw_html=True")
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    elapsed_ms: float = 0.0


# =============================================================================
# CVE / Vulnerability Results
# =============================================================================


class CVSSScore(BaseModel):
    """CVSS score information."""

    version: str = "3.1"
    base_score: float = Field(ge=0.0, le=10.0)
    vector: str = ""
    severity: Severity = Severity.INFO


class CVEReference(BaseModel):
    """External reference for a CVE."""

    url: str
    source: str = ""
    tags: list[str] = Field(default_factory=list)


class CVEResult(BaseModel):
    """
    Normalized CVE result.

    This model provides a unified format for CVE data regardless of source
    (NVD, Vulners, CIRCL, etc.).
    """

    id: str = Field(..., description="CVE ID (e.g., CVE-2023-12345)")
    source: str = Field(..., description="Data source: nvd, vulners, circl")
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cvss: CVSSScore | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    references: list[CVEReference] = Field(default_factory=list)
    published_date: datetime | None = None
    last_modified: datetime | None = None
    exploitability_score: float | None = Field(None, ge=0.0, le=10.0)
    impact_score: float | None = Field(None, ge=0.0, le=10.0)
    is_exploited: bool = False
    raw_data: dict[str, Any] | None = Field(
        None, description="Original API response for debugging"
    )


# =============================================================================
# Technology Fingerprint Results
# =============================================================================


class TechnologyMatch(BaseModel):
    """A detected technology/framework."""

    name: str
    version: str | None = None
    category: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence that led to detection (header, cookie, etc.)",
    )
    website: str | None = None
    cpe: str | None = Field(None, description="CPE identifier for CVE lookup")


class FingerprintResult(BaseModel):
    """Complete fingerprinting result."""

    technologies: list[TechnologyMatch] = Field(default_factory=list)
    server: str | None = None
    powered_by: str | None = None
    framework: str | None = None
    cms: str | None = None
    cdn: str | None = None
    waf: str | None = None


# =============================================================================
# SSL/TLS Analysis Results
# =============================================================================


class CertificateInfo(BaseModel):
    """SSL certificate information."""

    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    serial_number: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_until_expiry: int | None = None
    is_expired: bool = False
    is_self_signed: bool = False
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_bits: int = 0


class SSLFinding(BaseModel):
    """A security finding from SSL analysis."""

    title: str
    description: str
    severity: Severity
    recommendation: str = ""


class SSLResult(BaseModel):
    """Complete SSL/TLS analysis result."""

    is_https: bool = False
    protocol_version: str = ""
    cipher_suite: str = ""
    certificate: CertificateInfo | None = None
    chain_valid: bool | None = None
    ocsp_stapling: bool | None = None
    findings: list[SSLFinding] = Field(default_factory=list)
    grade: str | None = Field(None, description="Overall grade: A+, A, B, C, D, F")


# =============================================================================
# Security Headers Analysis
# =============================================================================


class HeaderFinding(BaseModel):
    """A finding related to security headers."""

    header: str
    present: bool
    value: str | None = None
    severity: Severity = Severity.INFO
    recommendation: str = ""


class HeadersResult(BaseModel):
    """Security headers analysis result."""

    findings: list[HeaderFinding] = Field(default_factory=list)
    score: int = Field(
        default=0, ge=0, le=100, description="Security headers score 0-100"
    )


# =============================================================================
# Attack Simulation Results
# =============================================================================


class AttackPayload(BaseModel):
    """Details of an attack payload."""

    type: str  # xss, sqli, traversal, etc.
    payload: str
    parameter: str = ""
    method: str = "GET"


class VulnerabilityFinding(BaseModel):
    """A vulnerability found during attack simulation."""

    type: str  # xss, sqli, path_traversal, etc.
    title: str
    description: str
    severity: Severity
    confidence: ConfidenceLevel
    url: str
    payload: AttackPayload
    evidence: str = Field(
        default="", description="Response snippet showing vulnerability"
    )
    remediation: str = ""
    cwe_id: str | None = None
    owasp_category: str | None = None


class AttackResult(BaseModel):
    """Complete attack simulation result."""

    target_url: str
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    total_payloads_tested: int = 0
    total_findings: int = 0
    xss_findings: int = 0
    sqli_findings: int = 0
    traversal_findings: int = 0
    enumeration_findings: int = 0
    duration_seconds: float = 0.0


# =============================================================================
# Complete Analysis Report
# =============================================================================


class AnalysisReport(BaseModel):
    """
    Complete analysis report combining all results.

    This is the main output model for a full scan.
    """

    meta: ExportMeta
    scrape: ScrapeResult | None = None
    fingerprint: FingerprintResult | None = None
    ssl: SSLResult | None = None
    headers: HeadersResult | None = None
    cves: list[CVEResult] = Field(default_factory=list)
    attack: AttackResult | None = None

    # Summary fields
    risk_score: int = Field(
        default=0, ge=0, le=100, description="Overall risk score 0-100"
    )
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0

    def calculate_summary(self) -> None:
        """Calculate summary statistics from all findings."""
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }

        # Count SSL findings
        if self.ssl:
            for f in self.ssl.findings:
                severity_counts[f.severity] += 1

        # Count header findings
        if self.headers:
            for f in self.headers.findings:
                if not f.present:  # Missing headers are findings
                    severity_counts[f.severity] += 1

        # Count CVE severities
        for cve in self.cves:
            severity_counts[cve.severity] += 1

        # Count attack findings
        if self.attack:
            for v in self.attack.vulnerabilities:
                severity_counts[v.severity] += 1

        self.critical_findings = severity_counts[Severity.CRITICAL]
        self.high_findings = severity_counts[Severity.HIGH]
        self.medium_findings = severity_counts[Severity.MEDIUM]
        self.low_findings = severity_counts[Severity.LOW]
        self.info_findings = severity_counts[Severity.INFO]

        # Calculate risk score (weighted)
        total = sum(severity_counts.values())
        if total > 0:
            self.risk_score = min(
                100,
                (
                    self.critical_findings * 40
                    + self.high_findings * 20
                    + self.medium_findings * 10
                    + self.low_findings * 5
                ),
            )
