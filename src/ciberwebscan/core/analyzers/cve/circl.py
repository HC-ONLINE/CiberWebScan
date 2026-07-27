"""
CIRCL (Computer Incident Response Center Luxembourg) CVE client.

This module provides access to the CIRCL CVE database API for searching
and retrieving vulnerability information.

API Documentation: https://cve.circl.lu/
"""

from __future__ import annotations

import logging
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
DEFAULT_API_URL = "https://cve.circl.lu/api/search/{vendor}/{product}"
DEFAULT_TIMEOUT = 30
DEFAULT_THROTTLE = 1.0  # Seconds between requests


class CIRCLClient:
    """
    Client for the CIRCL CVE API.

    Provides methods to search and retrieve CVE information from
    the Computer Incident Response Center Luxembourg database.

    Attributes:
        api_url: Base URL for the CIRCL API.
        timeout: Request timeout in seconds.
        throttle: Minimum time between requests.
    """

    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT,
        throttle: float = DEFAULT_THROTTLE,
    ) -> None:
        """
        Initialize the CIRCL client.

        Args:
            api_url: Base URL for the CIRCL API with {vendor}/{product} placeholders.
            timeout: Request timeout in seconds.
            throttle: Minimum seconds between API requests.
        """
        self.api_url = api_url
        self.timeout = timeout
        self.throttle = throttle

        # HTTPClient with built-in rate limiting (1/throttle requests per second)
        rate_limit = 1.0 / throttle if throttle > 0 else None
        self._http_client = HTTPClient(
            timeout=timeout,
            rate_limit=rate_limit,
            max_attempts=2,
        )

        logger.debug(
            "CIRCLClient initialized with timeout=%s, throttle=%s", timeout, throttle
        )

    def search(self, query: CVESearchQuery) -> CVESearchResult:
        """
        Search for CVEs matching the query.

        Args:
            query: Search parameters including vendor, product, and filters.

        Returns:
            CVESearchResult with matching entries.
        """
        start_time = time.perf_counter()

        if not query.vendor or not query.product:
            return CVESearchResult(
                source=CVESource.CIRCL,
                error="CIRCL requires both vendor and product parameters",
            )

        url = self.api_url.format(
            vendor=query.vendor.lower(),
            product=query.product.lower(),
        )

        try:
            response = self._http_client.get(url)

            if response.status_code != 200:
                logger.warning(
                    "CIRCL API returned status %d for %s/%s",
                    response.status_code,
                    query.vendor,
                    query.product,
                )
                return CVESearchResult(
                    source=CVESource.CIRCL,
                    error=f"HTTP {response.status_code}",
                    query_time_ms=(time.perf_counter() - start_time) * 1000,
                )

            data = response.json()

        except httpx.TimeoutException:
            logger.error("CIRCL API timeout for %s/%s", query.vendor, query.product)
            return CVESearchResult(
                source=CVESource.CIRCL,
                error="Request timeout",
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )
        except Exception as e:
            logger.error(
                "CIRCL API error for %s/%s: %s", query.vendor, query.product, e
            )
            return CVESearchResult(
                source=CVESource.CIRCL,
                error=str(e),
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        # Parse response
        entries = self._parse_response(data, query)

        # Apply filters
        if query.min_severity:
            entries = [
                e for e in entries if self._meets_severity(e, query.min_severity)
            ]

        # Apply limit
        if query.limit and len(entries) > query.limit:
            entries = entries[: query.limit]

        return CVESearchResult(
            source=CVESource.CIRCL,
            entries=entries,
            total_count=len(entries),
            query_time_ms=(time.perf_counter() - start_time) * 1000,
        )

    def _parse_response(self, data: Any, query: CVESearchQuery) -> list[CVEEntry]:
        """Parse CIRCL API response into CVEEntry objects."""
        entries: list[CVEEntry] = []

        if isinstance(data, list):
            # Direct list of CVEs
            for item in data:
                if isinstance(item, dict):
                    entry = self._parse_cve_item(item, query)
                    if entry:
                        entries.append(entry)
            return entries

        if not isinstance(data, dict):
            logger.warning("Unexpected CIRCL response format: %s", type(data))
            return entries

        # Handle different response formats
        if "vulnerabilities" in data:
            entries = self._parse_vulnerabilities_format(data["vulnerabilities"], query)
        elif "results" in data:
            entries = self._parse_results_format(data["results"], query)
        else:
            # Try parsing as direct list
            for key in ["cvelistv5", "fkie_nvd"]:
                if key in data:
                    entries = self._parse_legacy_format(data[key], query)
                    break

        return entries

    def _parse_cve_item(self, item: dict, query: CVESearchQuery) -> CVEEntry | None:
        """Parse a single CVE item from the response."""
        cve_id = item.get("id", "")
        if not cve_id:
            return None

        # Parse CVSS data
        cvss_data = None
        cvss = item.get("cvss")
        if isinstance(cvss, int | float):
            cvss_data = CVSSData(base_score=float(cvss), version="2.0")
        elif isinstance(cvss, dict) and "score" in cvss:
            cvss_data = CVSSData(
                base_score=float(cvss["score"]),
                version=cvss.get("version", "2.0"),
                vector_string=cvss.get("vector", ""),
            )

        entry = CVEEntry(
            id=cve_id,
            source=CVESource.CIRCL,
            description=item.get("summary", ""),
            cvss=cvss_data,
            affected_products=[
                AffectedProduct(vendor=query.vendor, product=query.product)
            ],
            raw_data=item,
        )

        # Parse published date
        published = item.get("Published", "")
        if published:
            entry.published_date = self._parse_date(published)

        return entry

    def _parse_vulnerabilities_format(
        self, items: list, query: CVESearchQuery
    ) -> list[CVEEntry]:
        """Parse 'vulnerabilities' format response."""
        entries = []
        for item in items:
            if not isinstance(item, dict):
                continue

            cve_id = item.get("id", "")
            if not cve_id:
                continue

            # Parse CVSS data
            cvss_data = None
            cvss = item.get("cvss", {})
            if isinstance(cvss, dict) and "score" in cvss:
                score = float(cvss["score"])
                cvss_data = CVSSData(
                    base_score=score,
                    version=cvss.get("version", "2.0"),
                    vector_string=cvss.get("vector", ""),
                )

            entry = CVEEntry(
                id=cve_id,
                source=CVESource.CIRCL,
                description=item.get("summary", ""),
                cvss=cvss_data,
                affected_products=[
                    AffectedProduct(vendor=query.vendor, product=query.product)
                ],
                raw_data=item,
            )

            # Parse published date
            published = item.get("Published", "")
            if published:
                entry.published_date = self._parse_date(published)

            entries.append(entry)

        return entries

    def _parse_results_format(
        self, items: list, query: CVESearchQuery
    ) -> list[CVEEntry]:
        """Parse 'results' format response."""
        entries = []
        for item in items:
            if not isinstance(item, dict):
                continue

            cve_id = item.get("cve_id", item.get("id", ""))
            if not cve_id:
                continue

            # Parse CVSS
            cvss_data = None
            if "cvss" in item:
                cvss_data = CVSSData(
                    base_score=item.get("cvss"),
                    version="2.0",
                )

            entry = CVEEntry(
                id=cve_id,
                source=CVESource.CIRCL,
                description=item.get("summary", item.get("description", "")),
                cvss=cvss_data,
                affected_products=[
                    AffectedProduct(vendor=query.vendor, product=query.product)
                ],
                raw_data=item,
            )

            entries.append(entry)

        return entries

    def _parse_legacy_format(
        self, items: list, query: CVESearchQuery
    ) -> list[CVEEntry]:
        """Parse legacy CVE list formats."""
        entries = []
        for item in items:
            if isinstance(item, list) and len(item) >= 2:
                cve_id = item[0] if isinstance(item[0], str) else ""
                details = item[1] if isinstance(item[1], dict) else {}
            elif isinstance(item, dict):
                cve_id = item.get("id", "")
                details = item
            else:
                continue

            if not cve_id:
                continue

            entry = CVEEntry(
                id=cve_id,
                source=CVESource.CIRCL,
                affected_products=[
                    AffectedProduct(vendor=query.vendor, product=query.product)
                ],
                raw_data=details,
            )

            # Extract description from various possible locations
            if "description" in details:
                desc = details["description"]
                if isinstance(desc, dict):
                    desc_data = desc.get("description_data", [])
                    for d in desc_data:
                        if isinstance(d, dict) and d.get("lang") == "en":
                            entry.description = d.get("value", "")
                            break
                elif isinstance(desc, str):
                    entry.description = desc

            entries.append(entry)

        return entries

    def _parse_date(self, date_str: str) -> datetime | None:
        """Parse date string to datetime."""
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
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

    def search_by_cve_id(self, cve_id: str) -> CVEEntry | None:
        """
        Get details for a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228).

        Returns:
            CVEEntry if found, None otherwise.
        """
        url = f"https://cve.circl.lu/api/cve/{cve_id}"

        try:
            response = self._http_client.get(url)

            if response.status_code != 200:
                return None

            data = response.json()

            if not isinstance(data, dict) or not data.get("id"):
                return None

            # Parse CVSS
            cvss_data = None
            cvss = data.get("cvss", {})
            if isinstance(cvss, dict) and "score" in cvss:
                cvss_data = CVSSData(
                    base_score=float(cvss["score"]),
                    version=cvss.get("version", "2.0"),
                )

            entry = CVEEntry(
                id=data["id"],
                source=CVESource.CIRCL,
                description=data.get("summary", ""),
                cvss=cvss_data,
                raw_data=data,
            )

            # Parse references
            refs = data.get("references", [])
            entry.references = [
                CVEReference(url=ref) for ref in refs if isinstance(ref, str)
            ]

            return entry

        except Exception as e:
            logger.error("Error fetching CVE %s from CIRCL: %s", cve_id, e)
            return None


def lookup_cves_circl(
    vendor: str,
    product: str,
    version: str = "",
    max_results: int = 50,
) -> list[CVEEntry]:
    """
    Convenience function to search CVEs via CIRCL.

    Args:
        vendor: Product vendor name.
        product: Product name.
        version: Optional version filter.
        max_results: Maximum number of results.

    Returns:
        List of matching CVEEntry objects.
    """
    client = CIRCLClient()
    query = CVESearchQuery(
        vendor=vendor,
        product=product,
        version=version,
        limit=max_results,
    )
    result = client.search(query)
    return result.entries
