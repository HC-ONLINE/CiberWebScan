"""
Vulners CVE and exploit client.

This module provides access to the Vulners API for searching
CVEs and exploit information.

API Documentation: https://vulners.com/api/v3/
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from ciberwebscan.core.client import HTTPClient

from .models import (
    CVEEntry,
    CVEReference,
    CVESearchResult,
    CVESource,
    CVSSData,
)

logger = logging.getLogger(__name__)


# Default configuration
DEFAULT_API_URL = "https://vulners.com/api/v3"
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 2


class VulnersClient:
    """
    Client for the Vulners API.

    Provides methods to search for CVEs and exploit information.
    Requires an API key for most operations.

    Attributes:
        api_key: Vulners API key.
        timeout: Request timeout in seconds.
        max_retries: Maximum retry attempts.
        enabled: Whether the client is enabled (has API key).
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        """
        Initialize the Vulners client.

        Args:
            api_key: Vulners API key (or set VULNERS_API_KEY env var).
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts.
        """
        self.api_key = api_key or os.environ.get("VULNERS_API_KEY", "")
        self.timeout = timeout
        self.max_retries = max_retries
        self.enabled = bool(self.api_key)

        self._http_client = HTTPClient(
            timeout=timeout,
            rate_limit=2.0,  # 2 requests per second
            max_retries=max_retries,
        )

        logger.debug(
            "VulnersClient initialized, enabled=%s",
            self.enabled,
        )

    def _post(self, endpoint: str, data: dict[str, Any]) -> httpx.Response:
        """Make a POST request to the Vulners API."""
        url = f"{DEFAULT_API_URL}/{endpoint}"

        if self.api_key:
            data["apiKey"] = self.api_key

        return self._http_client.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
        )

    def search_by_software(
        self,
        software: str,
        version: str = "",
        max_results: int = 50,
    ) -> CVESearchResult:
        """
        Search for vulnerabilities by software name and version.

        Args:
            software: Software name.
            version: Software version.
            max_results: Maximum results to return.

        Returns:
            CVESearchResult with matching entries.
        """
        start_time = time.perf_counter()

        if not self.enabled:
            return CVESearchResult(
                source=CVESource.VULNERS,
                error="Vulners API key not configured",
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        data = {
            "software": software,
            "version": version or "*",
            "maxVulnerabilities": max_results,
            "type": "software",
        }

        try:
            response = self._post("burp/software/", data)

            if response.status_code != 200:
                logger.warning("Vulners API returned status %d", response.status_code)
                return CVESearchResult(
                    source=CVESource.VULNERS,
                    error=f"HTTP {response.status_code}",
                    query_time_ms=(time.perf_counter() - start_time) * 1000,
                )

            result = response.json()

            if result.get("result") != "OK":
                error = result.get("data", {}).get("error", "Unknown error")
                return CVESearchResult(
                    source=CVESource.VULNERS,
                    error=error,
                    query_time_ms=(time.perf_counter() - start_time) * 1000,
                )

            entries = self._parse_software_response(result.get("data", {}))

            return CVESearchResult(
                source=CVESource.VULNERS,
                entries=entries,
                total_count=len(entries),
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        except httpx.TimeoutException:
            logger.error("Vulners API timeout")
            return CVESearchResult(
                source=CVESource.VULNERS,
                error="Request timeout",
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )
        except Exception as e:
            logger.error("Vulners API error: %s", e)
            return CVESearchResult(
                source=CVESource.VULNERS,
                error=str(e),
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

    def search_by_cpe(self, cpe: str, max_results: int = 50) -> CVESearchResult:
        """
        Search for vulnerabilities by CPE.

        Args:
            cpe: CPE string (e.g., cpe:2.3:a:vendor:product:version).
            max_results: Maximum results to return.

        Returns:
            CVESearchResult with matching entries.
        """
        start_time = time.perf_counter()

        if not self.enabled:
            return CVESearchResult(
                source=CVESource.VULNERS,
                error="Vulners API key not configured",
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        data = {
            "cpe": cpe,
            "maxVulnerabilities": max_results,
        }

        try:
            response = self._post("burp/packages/", data)

            if response.status_code != 200:
                return CVESearchResult(
                    source=CVESource.VULNERS,
                    error=f"HTTP {response.status_code}",
                    query_time_ms=(time.perf_counter() - start_time) * 1000,
                )

            result = response.json()

            if result.get("result") != "OK":
                error = result.get("data", {}).get("error", "Unknown error")
                return CVESearchResult(
                    source=CVESource.VULNERS,
                    error=error,
                    query_time_ms=(time.perf_counter() - start_time) * 1000,
                )

            entries = self._parse_software_response(result.get("data", {}))

            return CVESearchResult(
                source=CVESource.VULNERS,
                entries=entries,
                total_count=len(entries),
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        except Exception as e:
            logger.error("Vulners CPE search error: %s", e)
            return CVESearchResult(
                source=CVESource.VULNERS,
                error=str(e),
                query_time_ms=(time.perf_counter() - start_time) * 1000,
            )

    def get_exploits(self, cve_id: str) -> list[dict[str, Any]]:
        """
        Get available exploits for a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228).

        Returns:
            List of exploit information dictionaries.
        """
        if not self.enabled:
            return []

        data = {
            "id": cve_id,
            "references": True,
        }

        try:
            response = self._post("search/id/", data)

            if response.status_code != 200:
                return []

            result = response.json()

            if result.get("result") != "OK":
                return []

            documents = result.get("data", {}).get("documents", {})
            exploits = []

            for doc_id, doc in documents.items():
                if doc.get("type") in ["exploit", "metasploit", "exploitdb"]:
                    exploits.append(
                        {
                            "id": doc_id,
                            "title": doc.get("title", ""),
                            "type": doc.get("type", ""),
                            "url": doc.get("href", ""),
                            "published": doc.get("published", ""),
                        }
                    )

            return exploits

        except Exception as e:
            logger.error("Error fetching exploits for %s: %s", cve_id, e)
            return []

    def get_cve_details(self, cve_id: str) -> CVEEntry | None:
        """
        Get detailed information for a specific CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            CVEEntry if found, None otherwise.
        """
        if not self.enabled:
            return None

        data = {
            "id": cve_id,
            "references": True,
        }

        try:
            response = self._post("search/id/", data)

            if response.status_code != 200:
                return None

            result = response.json()

            if result.get("result") != "OK":
                return None

            documents = result.get("data", {}).get("documents", {})
            cve_doc = documents.get(cve_id)

            if not cve_doc:
                return None

            # Parse CVSS
            cvss_data = None
            cvss = cve_doc.get("cvss", {})
            if isinstance(cvss, dict) and "score" in cvss:
                cvss_data = CVSSData(
                    base_score=float(cvss["score"]),
                    version=cvss.get("version", "2.0"),
                    vector_string=cvss.get("vector", ""),
                )

            entry = CVEEntry(
                id=cve_id,
                source=CVESource.VULNERS,
                title=cve_doc.get("title", ""),
                description=cve_doc.get("description", ""),
                cvss=cvss_data,
                raw_data=cve_doc,
            )

            # Check for exploits
            exploits = self.get_exploits(cve_id)
            entry.has_exploit = len(exploits) > 0

            # Parse references
            refs = cve_doc.get("references", [])
            entry.references = [
                CVEReference(url=ref) for ref in refs if isinstance(ref, str)
            ]

            return entry

        except Exception as e:
            logger.error("Error fetching CVE %s from Vulners: %s", cve_id, e)
            return None

    def _parse_software_response(self, data: dict) -> list[CVEEntry]:
        """Parse Vulners software search response."""
        entries: list[CVEEntry] = []

        # Handle different response formats
        search_results = data.get("search", [])

        for item in search_results:
            if isinstance(item, dict):
                source = item.get("_source", item)
            else:
                continue

            cve_id = source.get("id", "")
            if not cve_id:
                continue

            # Parse CVSS
            cvss_data = None
            cvss = source.get("cvss", {})
            if isinstance(cvss, dict) and "score" in cvss:
                cvss_data = CVSSData(
                    base_score=float(cvss["score"]),
                    version=cvss.get("version", "2.0"),
                )

            entry = CVEEntry(
                id=cve_id,
                source=CVESource.VULNERS,
                title=source.get("title", ""),
                description=source.get("description", ""),
                cvss=cvss_data,
                raw_data=source,
            )

            # Check exploit type
            entry.has_exploit = source.get("type") in ["exploit", "metasploit"]

            entries.append(entry)

        return entries


def get_exploit_info(
    cve_id: str,
    api_key: str | None = None,
) -> dict[str, Any]:
    """
    Convenience function to get exploit information for a CVE.

    Args:
        cve_id: CVE identifier.
        api_key: Optional Vulners API key.

    Returns:
        Dictionary with exploit information.
    """
    client = VulnersClient(api_key=api_key)

    if not client.enabled:
        return {
            "cve_id": cve_id,
            "has_exploits": False,
            "exploits": [],
            "error": "API key not configured",
        }

    exploits = client.get_exploits(cve_id)

    return {
        "cve_id": cve_id,
        "has_exploits": len(exploits) > 0,
        "exploits": exploits,
        "count": len(exploits),
    }
