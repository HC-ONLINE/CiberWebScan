"""
CVE analyzer internal models.

These models represent the internal data structures used by CVE lookup clients
and the aggregator. They are designed to normalize data from different sources
(NVD, CIRCL, Vulners) into a common format.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)


class CVESource(str, Enum):
    """Supported CVE data sources."""

    NVD = "nvd"
    CIRCL = "circl"
    VULNERS = "vulners"
    UNKNOWN = "unknown"


class CVESeverity(str, Enum):
    """CVE severity levels (CVSS v3 based)."""

    CRITICAL = "critical"  # 9.0 - 10.0
    HIGH = "high"  # 7.0 - 8.9
    MEDIUM = "medium"  # 4.0 - 6.9
    LOW = "low"  # 0.1 - 3.9
    NONE = "none"  # 0.0
    UNKNOWN = "unknown"

    @classmethod
    def from_cvss_score(cls, score: float | None) -> CVESeverity:
        """Determine severity from CVSS score."""
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE


@dataclass
class CVSSData:
    """CVSS score information."""

    version: str = "3.1"
    base_score: float | None = None
    vector_string: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality_impact: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""
    exploitability_score: float | None = None
    impact_score: float | None = None

    @property
    def severity(self) -> CVESeverity:
        """Calculate severity from base score."""
        return CVESeverity.from_cvss_score(self.base_score)


@dataclass
class CVEReference:
    """External reference for a CVE."""

    url: str
    source: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class AffectedProduct:
    """Product affected by a CVE."""

    vendor: str = ""
    product: str = ""
    version_start: str = ""
    version_end: str = ""
    version_exact: str = ""
    cpe: str = ""  # CPE 2.3 identifier

    def matches_version(self, version: str) -> bool:
        """Check if a specific version is affected.

        Supports:
        - Exact match (version_exact)
        - Range match (version_start <= version < version_end)
        - Wildcard (no version constraints = affects all versions)
        """
        if not version:
            return True

        if self.version_exact and self.version_exact == version:
            return True

        if self.version_start or self.version_end:
            return self._in_range(version)

        return (
            not self.version_exact and not self.version_start and not self.version_end
        )

    def _in_range(self, version: str) -> bool:
        """Check if version falls within the affected range."""
        try:
            v = Version(version)
        except InvalidVersion:
            logger.debug("Cannot parse version '%s', assuming affected", version)
            return True

        if self.version_start:
            try:
                if v < Version(self.version_start):
                    return False
            except InvalidVersion:
                pass

        if self.version_end:
            try:
                if v >= Version(self.version_end):
                    return False
            except InvalidVersion:
                pass

        return True


@dataclass
class CVEEntry:
    """
    Normalized CVE entry from any source.

    This is the internal representation used by the aggregator.
    All CVE clients must convert their API responses to this format.
    """

    id: str  # CVE-YYYY-NNNNN format
    source: CVESource = CVESource.UNKNOWN
    title: str = ""
    description: str = ""
    cvss: CVSSData | None = None
    cwe_ids: list[str] = field(default_factory=list)
    affected_products: list[AffectedProduct] = field(default_factory=list)
    references: list[CVEReference] = field(default_factory=list)
    published_date: datetime | None = None
    last_modified_date: datetime | None = None
    is_rejected: bool = False
    is_disputed: bool = False
    has_exploit: bool = False
    epss_score: float | None = None  # Exploit Prediction Scoring System
    raw_data: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> CVESeverity:
        """Get severity from CVSS data."""
        if self.cvss:
            return self.cvss.severity
        return CVESeverity.UNKNOWN

    @property
    def score(self) -> float | None:
        """Get CVSS base score."""
        if self.cvss:
            return self.cvss.base_score
        return None

    def matches_product(self, vendor: str, product: str, version: str = "") -> bool:
        """Check if this CVE affects a specific product."""
        vendor_lower = vendor.lower()
        product_lower = product.lower()

        for affected in self.affected_products:
            if (
                affected.vendor.lower() == vendor_lower
                and affected.product.lower() == product_lower
                and (not version or affected.matches_version(version))
            ):
                return True
        return False


@dataclass
class CVESearchQuery:
    """Query parameters for CVE search."""

    # Product identification
    vendor: str = ""
    product: str = ""
    version: str = ""
    cpe: str = ""

    # Filters
    min_severity: CVESeverity | None = None
    min_cvss_score: float | None = None
    published_after: datetime | None = None
    published_before: datetime | None = None
    has_exploit: bool | None = None

    # Pagination
    limit: int = 50
    offset: int = 0

    # Sources
    sources: list[CVESource] = field(default_factory=lambda: list(CVESource))

    def to_nvd_params(self) -> dict[str, Any]:
        """Convert to NVD API query parameters."""
        params: dict[str, Any] = {}

        if self.cpe:
            params["cpeName"] = self.cpe
        elif self.vendor and self.product:
            params["keywordSearch"] = f"{self.vendor} {self.product}"

        if self.min_cvss_score:
            params["cvssV3Severity"] = CVESeverity.from_cvss_score(
                self.min_cvss_score
            ).value.upper()

        if self.published_after:
            params["pubStartDate"] = self.published_after.isoformat()
        if self.published_before:
            params["pubEndDate"] = self.published_before.isoformat()

        params["resultsPerPage"] = min(self.limit, 2000)  # NVD max is 2000
        params["startIndex"] = self.offset

        return params

    def to_circl_params(self) -> dict[str, Any]:
        """Convert to CIRCL API query parameters."""
        params: dict[str, Any] = {}

        if self.vendor:
            params["vendor"] = self.vendor
        if self.product:
            params["product"] = self.product

        return params

    def to_vulners_params(self) -> dict[str, Any]:
        """Convert to Vulners API query parameters."""
        params: dict[str, Any] = {}

        if self.product:
            params["software"] = self.product
        if self.version:
            params["version"] = self.version

        params["maxVulnerabilities"] = self.limit

        return params


@dataclass
class CVESearchResult:
    """Result of a CVE search operation."""

    entries: list[CVEEntry] = field(default_factory=list)
    total_count: int = 0
    source: CVESource = CVESource.UNKNOWN
    query_time_ms: float = 0.0
    cached: bool = False
    error: str | None = None

    @property
    def has_error(self) -> bool:
        """Check if search had an error."""
        return self.error is not None

    @property
    def is_empty(self) -> bool:
        """Check if no results were found."""
        return len(self.entries) == 0


@dataclass
class AggregatedCVEResult:
    """
    Aggregated result from multiple CVE sources.

    Combines and deduplicates results from NVD, CIRCL, and Vulners.
    """

    entries: list[CVEEntry] = field(default_factory=list)
    sources_queried: list[CVESource] = field(default_factory=list)
    sources_succeeded: list[CVESource] = field(default_factory=list)
    sources_failed: dict[CVESource, str] = field(default_factory=dict)
    total_query_time_ms: float = 0.0
    duplicates_removed: int = 0

    @property
    def all_sources_succeeded(self) -> bool:
        """Check if all queried sources returned successfully."""
        return len(self.sources_failed) == 0

    @property
    def by_severity(self) -> dict[CVESeverity, list[CVEEntry]]:
        """Group CVEs by severity."""
        result: dict[CVESeverity, list[CVEEntry]] = {s: [] for s in CVESeverity}
        for entry in self.entries:
            result[entry.severity].append(entry)
        return result

    @property
    def critical_count(self) -> int:
        """Count critical severity CVEs."""
        return sum(1 for e in self.entries if e.severity == CVESeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count high severity CVEs."""
        return sum(1 for e in self.entries if e.severity == CVESeverity.HIGH)

    def filter_by_severity(self, min_severity: CVESeverity) -> list[CVEEntry]:
        """Filter entries by minimum severity."""
        severity_order = [
            CVESeverity.NONE,
            CVESeverity.LOW,
            CVESeverity.MEDIUM,
            CVESeverity.HIGH,
            CVESeverity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)

        return [
            e
            for e in self.entries
            if e.severity != CVESeverity.UNKNOWN
            and severity_order.index(e.severity) >= min_index
        ]

    def sort_by_score(self, descending: bool = True) -> list[CVEEntry]:
        """Sort entries by CVSS score."""
        return sorted(
            self.entries,
            key=lambda e: e.score or 0.0,
            reverse=descending,
        )
