"""
NVD (National Vulnerability Database) CVE client.

This module provides access to the NVD API for searching
and retrieving vulnerability information.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from typing import Any

import httpx

from ciberwebscan.core.client import HTTPClient

from .models import (
    AffectedProduct,
    CVEEntry,
    CVEReference,
    CVESearchQuery,
    CVESearchResult,
    CVESeverity,
    CVESource,
    CVSSData,
)

logger = logging.getLogger(__name__)


# Default configuration
DEFAULT_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 45  # NVD can be slow
DEFAULT_RATE_LIMIT = 0.6  # ~100 requests per minute without API key


# Common product to CPE mappings for convenience
PRODUCT_TO_CPE: dict[str, str] = {
    "wordpress": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    "nginx": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    "apache": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "jquery": "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
    "php": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
    "mysql": "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
    "postgresql": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    "redis": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
    "mongodb": "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
    "django": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    "flask": "cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*",
    "react": "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*",
    "angular": "cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*",
    "vue": "cpe:2.3:a:vuejs:vue.js:*:*:*:*:*:*:*:*",
    "node": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
    "log4j": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "spring": "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    "tomcat": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    "drupal": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    "joomla": "cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*",
}


class NVDClient:
    """
    Client for the NVD CVE API.

    Provides methods to search and retrieve CVE information from
    the National Vulnerability Database.

    Attributes:
        api_url: Base URL for the NVD API.
        api_key: Optional API key for higher rate limits.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """
        Initialize the NVD client.

        Args:
            api_url: Base URL for the NVD API.
            api_key: Optional NVD API key (get from nvd.nist.gov).
            timeout: Request timeout in seconds.
        """
        self.api_url = api_url
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.timeout = timeout

        # Rate limit: 5 req/30s without key, 50 req/30s with key
        rate_limit = 1.5 if self.api_key else DEFAULT_RATE_LIMIT
        self._http_client = HTTPClient(
            timeout=timeout,
            rate_limit=rate_limit,
            max_attempts=2,
        )

        logger.debug(
            "NVDClient initialized with timeout=%s, api_key=%s",
            timeout,
            "set" if self.api_key else "not set",
        )

    def _get_headers(self) -> dict[str, str]:
        """Get headers for NVD API requests."""
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def search(self, query: CVESearchQuery) -> CVESearchResult:
        """
        Search for CVEs matching the query.

        Args:
            query: Search parameters.

        Returns:
            CVESearchResult with matching entries.
        """
        start_time = time.perf_counter()

        # Build query parameters
        params: dict[str, Any] = {}

        # CPE-based search
        if query.cpe:
            params["cpeName"] = query.cpe
        elif query.product:
            # Try to find a CPE mapping
            cpe = PRODUCT_TO_CPE.get(query.product.lower())
            if cpe:
                params["cpeName"] = cpe
            else:
                # Fallback to keyword search
                keyword = query.product
                if query.vendor:
                    keyword = f"{query.vendor} {keyword}"
                params["keywordSearch"] = keyword

        # Pagination
        if query.limit:
            params["resultsPerPage"] = min(query.limit, 2000)
        if query.offset:
            params["startIndex"] = query.offset

        try:
            response = self._http_client.get(
                self.api_url,
                params=params,
                headers=self._get_headers(),
            )

            if response.status_code != 200:
                logger.warning("NVD API returned status %d", response.status_code)
                return CVESearchResult(
                    source=CVESource.NVD,
                    error=f"HTTP {response.status_code}",
                    query_time_ms=(time.perf_counter() - start_time) * 1000,
                )

            data = response.json()

        except httpx.TimeoutException:
            logger.error("NVD API timeout")
            return CVESearchResult(
                source=CVESource.NVD,
                error="Request timeout",
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )
        except Exception as e:
            logger.error("NVD API error: %s", e)
            return CVESearchResult(
                source=CVESource.NVD,
                error=str(e),
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        # Parse response
        entries = self._parse_response(data)

        # Apply severity filter
        if query.min_severity:
            entries = [
                e for e in entries if self._meets_severity(e, query.min_severity)
            ]

        return CVESearchResult(
            source=CVESource.NVD,
            entries=entries,
            total_count=data.get("totalResults", len(entries)),
            query_time_ms=(time.perf_counter() - start_time) * 1000,
        )

    def _parse_response(self, data: dict) -> list[CVEEntry]:
        """Parse NVD API response into CVEEntry objects."""
        entries: list[CVEEntry] = []

        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            if not cve_id:
                continue

            # Get English description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Parse CVSS data (prefer v3.1, fallback to v3.0, then v2)
            cvss_data = self._parse_cvss(cve_data.get("metrics", {}))

            # Parse dates
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            entry = CVEEntry(
                id=cve_id,
                source=CVESource.NVD,
                description=description,
                cvss=cvss_data,
                published_date=self._parse_date(published),
                last_modified_date=self._parse_date(modified),
                raw_data=cve_data,
            )

            # Parse references
            refs = cve_data.get("references", [])
            entry.references = [
                CVEReference(
                    url=ref.get("url", ""),
                    source=ref.get("source", ""),
                    tags=ref.get("tags", []),
                )
                for ref in refs
                if ref.get("url")
            ]

            # Parse CWE IDs
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        value = desc.get("value", "")
                        if value.startswith("CWE-"):
                            cwe_ids.append(value)
            entry.cwe_ids = cwe_ids

            # Parse affected products from configurations
            entry.affected_products = self._parse_configurations(
                cve_data.get("configurations", [])
            )

            entries.append(entry)

        return entries

    def _parse_cvss(self, metrics: dict) -> CVSSData | None:
        """Parse CVSS data from metrics, preferring newer versions."""
        # Try CVSS 3.1 first
        for metric in metrics.get("cvssMetricV31", []):
            cvss = metric.get("cvssData", {})
            if cvss:
                return CVSSData(
                    version=cvss.get("version", "3.1"),
                    base_score=cvss.get("baseScore", 0.0),
                    vector_string=cvss.get("vectorString", ""),
                    impact_score=metric.get("impactScore"),
                    exploitability_score=metric.get("exploitabilityScore"),
                )

        # Try CVSS 3.0
        for metric in metrics.get("cvssMetricV30", []):
            cvss = metric.get("cvssData", {})
            if cvss:
                return CVSSData(
                    version=cvss.get("version", "3.0"),
                    base_score=cvss.get("baseScore", 0.0),
                    vector_string=cvss.get("vectorString", ""),
                    impact_score=metric.get("impactScore"),
                    exploitability_score=metric.get("exploitabilityScore"),
                )

        # Fallback to CVSS 2.0
        for metric in metrics.get("cvssMetricV2", []):
            cvss = metric.get("cvssData", {})
            if cvss:
                return CVSSData(
                    version="2.0",
                    base_score=cvss.get("baseScore", 0.0),
                    vector_string=cvss.get("vectorString", ""),
                    impact_score=metric.get("impactScore"),
                    exploitability_score=metric.get("exploitabilityScore"),
                )

        return None

    def _parse_configurations(self, configurations: list) -> list[AffectedProduct]:
        """Parse CPE configurations to extract affected products."""
        products: list[AffectedProduct] = []

        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue

                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")

                    if len(parts) >= 6:
                        vendor = parts[3] if parts[3] != "*" else ""
                        product = parts[4] if parts[4] != "*" else ""
                        version = parts[5] if parts[5] != "*" else ""

                        products.append(
                            AffectedProduct(
                                vendor=vendor,
                                product=product,
                                version_exact=version or "",
                                version_start=match.get("versionStartIncluding"),
                                version_end=match.get("versionEndExcluding"),
                                cpe=cpe,
                            )
                        )

        return products

    def _parse_date(self, date_str: str) -> datetime | None:
        """Parse ISO date string to datetime."""
        if not date_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str.rstrip("Z"), fmt)
            except ValueError:
                continue

        return None

    def _meets_severity(self, entry: CVEEntry, min_severity: CVESeverity) -> bool:
        """Check if entry meets minimum severity requirement."""
        severity_order = [
            CVESeverity.NONE,
            CVESeverity.UNKNOWN,
            CVESeverity.LOW,
            CVESeverity.MEDIUM,
            CVESeverity.HIGH,
            CVESeverity.CRITICAL,
        ]
        try:
            entry_idx = severity_order.index(entry.severity)
            min_idx = severity_order.index(min_severity)
            return entry_idx >= min_idx
        except ValueError:
            return True

    def get_cve(self, cve_id: str) -> CVEEntry | None:
        """
        Get details for a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228).

        Returns:
            CVEEntry if found, None otherwise.
        """
        params = {"cveId": cve_id}

        try:
            response = self._http_client.get(
                self.api_url,
                params=params,
                headers=self._get_headers(),
            )

            if response.status_code != 200:
                return None

            data = response.json()
            entries = self._parse_response(data)

            return entries[0] if entries else None

        except Exception as e:
            logger.error("Error fetching CVE %s from NVD: %s", cve_id, e)
            return None

    def clear_cache(self) -> None:
        """Clear any cached data."""
        # For future cache implementation
        pass


def lookup_cves_nvd(
    product: str,
    vendor: str = "",
    version: str = "",
    max_results: int = 50,
) -> CVESearchResult:
    """
    Convenience function to search CVEs via NVD.

    Args:
        product: Product name to search for.
        vendor: Optional vendor name.
        version: Optional version filter.
        max_results: Maximum number of results.

    Returns:
        CVESearchResult with matching entries.
    """
    client = NVDClient()
    query = CVESearchQuery(
        vendor=vendor,
        product=product,
        version=version,
        limit=max_results,
    )
    return client.search(query)
