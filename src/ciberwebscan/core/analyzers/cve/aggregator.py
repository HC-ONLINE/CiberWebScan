"""
CVE aggregator that combines results from multiple sources.

This module provides a unified interface to query multiple CVE databases
(NVD, CIRCL, Vulners) and returns normalized, deduplicated results.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from .circl import CIRCLClient
from .models import (
    AggregatedCVEResult,
    CVEEntry,
    CVESearchQuery,
    CVESearchResult,
    CVESeverity,
    CVESource,
)
from .nvd import NVDClient
from .vulners import VulnersClient

logger = logging.getLogger(__name__)


class CVEAggregator:
    """
    Aggregates CVE data from multiple sources.

    Provides a unified interface to search across NVD, CIRCL, and Vulners,
    combining and deduplicating results with consistent formatting.

    Attributes:
        sources: List of enabled CVE sources.
        nvd_client: NVD API client.
        circl_client: CIRCL API client.
        vulners_client: Vulners API client.
    """

    def __init__(
        self,
        sources: list[CVESource] | None = None,
        nvd_api_key: str = "",
        vulners_api_key: str = "",
        cache_ttl: int = 86400,
    ) -> None:
        """
        Initialize the CVE aggregator.

        Args:
            sources: List of CVE sources to query. Defaults to [NVD, CIRCL].
            nvd_api_key: Optional NVD API key for higher rate limits.
            vulners_api_key: Optional Vulners API key.
            cache_ttl: Time-to-live in seconds for cached results.
        """
        self.sources = sources or [CVESource.NVD, CVESource.CIRCL]
        self.cache_ttl = cache_ttl

        # Initialize clients
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.circl_client = CIRCLClient()
        self.vulners_client = VulnersClient(api_key=vulners_api_key)

        logger.debug(
            "CVEAggregator initialized with sources: %s",
            [s.value for s in self.sources],
        )

    def search(
        self,
        product: str,
        vendor: str = "",
        version: str = "",
        limit: int = 50,
        min_severity: CVESeverity | None = None,
        sources: list[CVESource] | None = None,
    ) -> AggregatedCVEResult:
        """
        Search for CVEs across multiple sources.

        Args:
            product: Product name to search.
            vendor: Optional vendor/manufacturer name.
            version: Optional version string.
            limit: Maximum results per source.
            min_severity: Minimum severity filter.
            sources: Override default sources for this query.

        Returns:
            AggregatedCVEResult with combined, deduplicated entries.
        """
        start_time = time.perf_counter()

        query = CVESearchQuery(
            vendor=vendor or product,  # Use product as vendor if not specified
            product=product,
            version=version,
            limit=limit,
            min_severity=min_severity,
        )

        active_sources = sources or self.sources
        results: list[CVESearchResult] = []

        # Query each source
        for source in active_sources:
            result = self._query_source(source, query)
            results.append(result)

        # Combine and deduplicate
        aggregated = self._aggregate_results(results, active_sources)
        aggregated.total_query_time_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "CVE aggregation complete: %d entries from %d sources in %.1fms",
            len(aggregated.entries),
            len(aggregated.sources_succeeded),
            aggregated.total_query_time_ms,
        )

        return aggregated

    def _query_source(
        self, source: CVESource, query: CVESearchQuery
    ) -> CVESearchResult:
        """Query a single CVE source."""
        try:
            if source == CVESource.NVD:
                return self.nvd_client.search(query)
            elif source == CVESource.CIRCL:
                return self.circl_client.search(query)
            elif source == CVESource.VULNERS:
                return self.vulners_client.search_by_software(
                    query.product,
                    query.version,
                    query.limit,
                )
            else:
                return CVESearchResult(
                    source=source,
                    error=f"Unknown source: {source}",
                )
        except Exception as e:
            logger.error("Error querying %s: %s", source.value, e)
            return CVESearchResult(
                source=source,
                error=str(e),
            )

    def _aggregate_results(
        self,
        results: list[CVESearchResult],
        sources_queried: list[CVESource],
    ) -> AggregatedCVEResult:
        """Combine and deduplicate results from multiple sources."""
        aggregated = AggregatedCVEResult(
            sources_queried=sources_queried,
        )

        # Track entries by CVE ID for deduplication
        entries_by_id: dict[str, CVEEntry] = {}
        duplicates = 0

        for result in results:
            if result.has_error:
                aggregated.sources_failed[result.source] = (
                    result.error or "Unknown error"
                )
            else:
                aggregated.sources_succeeded.append(result.source)

            for entry in result.entries:
                if entry.id in entries_by_id:
                    # Merge information from duplicate
                    existing = entries_by_id[entry.id]
                    self._merge_entries(existing, entry)
                    duplicates += 1
                else:
                    entries_by_id[entry.id] = entry

        aggregated.entries = list(entries_by_id.values())
        aggregated.duplicates_removed = duplicates

        # Sort by severity (critical first), then by score
        aggregated.entries.sort(
            key=lambda e: (
                -self._severity_score(e.severity),
                -(e.score or 0),
            )
        )

        return aggregated

    def _merge_entries(self, existing: CVEEntry, new: CVEEntry) -> None:
        """Merge information from a duplicate entry into the existing one."""
        # Prefer longer description
        if len(new.description) > len(existing.description):
            existing.description = new.description

        # Merge references
        existing_urls = {r.url for r in existing.references}
        for ref in new.references:
            if ref.url not in existing_urls:
                existing.references.append(ref)

        # Merge CWE IDs
        existing.cwe_ids = list(set(existing.cwe_ids) | set(new.cwe_ids))

        # Take exploit flag if any source reports it
        existing.has_exploit = existing.has_exploit or new.has_exploit

        # Prefer CVSS 3.1 over older versions
        if new.cvss and existing.cvss:
            if new.cvss.version > existing.cvss.version:
                existing.cvss = new.cvss
        elif new.cvss and not existing.cvss:
            existing.cvss = new.cvss

    def _severity_score(self, severity: CVESeverity) -> int:
        """Convert severity to numeric score for sorting."""
        scores = {
            CVESeverity.CRITICAL: 5,
            CVESeverity.HIGH: 4,
            CVESeverity.MEDIUM: 3,
            CVESeverity.LOW: 2,
            CVESeverity.NONE: 1,
            CVESeverity.UNKNOWN: 0,
        }
        return scores.get(severity, 0)

    def get_cve(self, cve_id: str) -> CVEEntry | None:
        """
        Get details for a specific CVE from the first available source.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228).

        Returns:
            CVEEntry if found, None otherwise.
        """
        for source in self.sources:
            try:
                if source == CVESource.NVD:
                    entry = self.nvd_client.get_cve(cve_id)
                elif source == CVESource.CIRCL:
                    entry = self.circl_client.search_by_cve_id(cve_id)
                elif source == CVESource.VULNERS:
                    entry = self.vulners_client.get_cve_details(cve_id)
                else:
                    continue

                if entry:
                    return entry

            except Exception as e:
                logger.warning("Error fetching %s from %s: %s", cve_id, source.value, e)
                continue

        return None

    def enrich_with_exploits(self, entry: CVEEntry) -> list[dict[str, Any]]:
        """
        Enrich a CVE entry with exploit information from Vulners.

        Args:
            entry: CVE entry to enrich.

        Returns:
            Dictionary with exploit information.
        """
        return self.vulners_client.get_exploits(entry.id)


# Convenience type alias for backward compatibility
CVSSMetrics = Any  # Alias for CVSSData


def lookup_cves(
    product: str,
    vendor: str = "",
    version: str = "",
    max_results: int = 50,
    sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Convenience function to lookup CVEs with normalized output.

    Args:
        product: Product name to search.
        vendor: Optional vendor name.
        version: Optional version string.
        max_results: Maximum results.
        sources: List of source names ("nvd", "circl", "vulners").

    Returns:
        List of CVE dictionaries in normalized format.
    """
    # Convert source strings to enum
    source_map = {
        "nvd": CVESource.NVD,
        "circl": CVESource.CIRCL,
        "vulners": CVESource.VULNERS,
    }
    source_list = None
    if sources:
        source_list = [
            source_map[s.lower()] for s in sources if s.lower() in source_map
        ]

    aggregator = CVEAggregator()
    result = aggregator.search(
        product=product,
        vendor=vendor,
        version=version,
        limit=max_results,
        sources=source_list,
    )

    # Convert to dict format
    output = []
    for entry in result.entries:
        cve_dict = {
            "id": entry.id,
            "source": entry.source.value,
            "severity": entry.severity.value,
            "cvss_score": entry.score,
            "cvss_version": entry.cvss.version if entry.cvss else None,
            "description": entry.description,
            "published_date": entry.published_date.isoformat()
            if entry.published_date
            else None,
            "references": [ref.url for ref in entry.references],
            "cwe_ids": entry.cwe_ids,
            "has_exploit": entry.has_exploit,
        }
        output.append(cve_dict)

    return output
