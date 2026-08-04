"""
CVE analyzer module.

Provides unified CVE lookup from multiple sources (NVD, CIRCL, Vulners)
with normalization to a common format.

Usage example:
    >>> from ciberwebscan.core.analyzers.cve import CVEAggregator
    >>> aggregator = CVEAggregator()
    >>> result = aggregator.search("wordpress", version="5.8")
    >>> for entry in result.entries:
    ...     print(f"{entry.id}: {entry.severity.value} - {entry.description[:50]}")

    # Or use convenience function
    >>> from ciberwebscan.core.analyzers.cve import lookup_cves
    >>> cves = lookup_cves("nginx", version="1.19")
"""

from __future__ import annotations

from ciberwebscan.core.analyzers.cve.aggregator import (
    CVEAggregator,
    lookup_cves,
)
from ciberwebscan.core.analyzers.cve.circl import (
    CIRCLClient,
    lookup_cves_circl,
)
from ciberwebscan.core.analyzers.cve.models import (
    AffectedProduct,
    AggregatedCVEResult,
    CVEEntry,
    CVEReference,
    CVESearchQuery,
    CVESearchResult,
    CVESeverity,
    CVESource,
    CVSSData,
)
from ciberwebscan.core.analyzers.cve.nvd import (
    NVDClient,
    lookup_cves_nvd,
)
from ciberwebscan.core.analyzers.cve.vulners import (
    VulnersClient,
    get_exploit_info,
)

__all__ = [
    # Main aggregator
    "CVEAggregator",
    "lookup_cves",
    # Individual clients
    "CIRCLClient",
    "NVDClient",
    "VulnersClient",
    # Convenience functions
    "lookup_cves_circl",
    "lookup_cves_nvd",
    "get_exploit_info",
    # Enums
    "CVESource",
    "CVESeverity",
    # Data classes
    "CVSSData",
    "CVEReference",
    "AffectedProduct",
    "CVEEntry",
    # Query/Result
    "CVESearchQuery",
    "CVESearchResult",
    "AggregatedCVEResult",
]
