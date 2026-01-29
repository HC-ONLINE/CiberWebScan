"""
CVE analyzer module.

Provides unified CVE lookup from multiple sources (NVD, CIRCL, Vulners)
with normalization to a common format.
"""

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

__all__ = [
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
