"""
Unit tests for CVE models.

Tests the data structures and enums used across CVE clients.
"""

from datetime import datetime

import pytest

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


class TestCVESource:
    """Tests for CVESource enum."""

    def test_all_sources_defined(self) -> None:
        """Verify all expected sources are defined."""
        assert CVESource.NVD.value == "nvd"
        assert CVESource.CIRCL.value == "circl"
        assert CVESource.VULNERS.value == "vulners"
        assert CVESource.UNKNOWN.value == "unknown"

    def test_source_from_string(self) -> None:
        """Test creating source from string value."""
        assert CVESource("nvd") == CVESource.NVD
        assert CVESource("circl") == CVESource.CIRCL


class TestCVESeverity:
    """Tests for CVESeverity enum."""

    def test_all_severities_defined(self) -> None:
        """Verify all severity levels are defined."""
        assert CVESeverity.CRITICAL.value == "critical"
        assert CVESeverity.HIGH.value == "high"
        assert CVESeverity.MEDIUM.value == "medium"
        assert CVESeverity.LOW.value == "low"
        assert CVESeverity.NONE.value == "none"
        assert CVESeverity.UNKNOWN.value == "unknown"

    @pytest.mark.parametrize(
        "score,expected",
        [
            (10.0, CVESeverity.CRITICAL),
            (9.5, CVESeverity.CRITICAL),
            (9.0, CVESeverity.CRITICAL),
            (8.9, CVESeverity.HIGH),
            (7.0, CVESeverity.HIGH),
            (6.9, CVESeverity.MEDIUM),
            (4.0, CVESeverity.MEDIUM),
            (3.9, CVESeverity.LOW),
            (0.1, CVESeverity.LOW),
            (0.0, CVESeverity.NONE),
            (None, CVESeverity.UNKNOWN),
        ],
    )
    def test_from_cvss_score(self, score: float | None, expected: CVESeverity) -> None:
        """Test severity classification from CVSS score."""
        assert CVESeverity.from_cvss_score(score) == expected

    def test_from_cvss_score_negative(self) -> None:
        """Test negative score returns NONE (as it's less than 0.1)."""
        # Negative scores are invalid but should not crash
        result = CVESeverity.from_cvss_score(-1.0)
        assert result == CVESeverity.NONE


class TestCVSSData:
    """Tests for CVSSData dataclass."""

    def test_create_cvss_v3(self) -> None:
        """Test creating CVSS v3 data."""
        cvss = CVSSData(
            version="3.1",
            base_score=9.8,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        assert cvss.version == "3.1"
        assert cvss.base_score == 9.8
        assert "AV:N" in cvss.vector_string

    def test_create_cvss_with_impacts(self) -> None:
        """Test creating CVSS with impact scores."""
        cvss = CVSSData(
            version="3.1",
            base_score=7.5,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            impact_score=3.6,
            exploitability_score=3.9,
        )
        assert cvss.impact_score == 3.6
        assert cvss.exploitability_score == 3.9

    def test_cvss_defaults(self) -> None:
        """Test default values for CVSS data."""
        cvss = CVSSData(version="2.0", base_score=5.0)
        assert cvss.vector_string == ""
        assert cvss.impact_score is None
        assert cvss.exploitability_score is None

    def test_severity_property(self) -> None:
        """Test severity is computed from base_score."""
        cvss = CVSSData(version="3.1", base_score=9.5)
        assert cvss.severity == CVESeverity.CRITICAL


class TestCVEReference:
    """Tests for CVEReference dataclass."""

    def test_create_reference(self) -> None:
        """Test creating a CVE reference."""
        ref = CVEReference(
            url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            source="NVD",
            tags=["Vendor Advisory", "Third Party Advisory"],
        )
        assert "nvd.nist.gov" in ref.url
        assert ref.source == "NVD"
        assert len(ref.tags) == 2

    def test_reference_defaults(self) -> None:
        """Test default values for reference."""
        ref = CVEReference(url="https://example.com/advisory")
        assert ref.source == ""
        assert ref.tags == []


class TestAffectedProduct:
    """Tests for AffectedProduct dataclass."""

    def test_create_affected_product(self) -> None:
        """Test creating an affected product."""
        product = AffectedProduct(
            vendor="Apache",
            product="Log4j",
            version_exact="2.14.1",
            version_start="2.0-beta9",
            version_end="2.14.1",
        )
        assert product.vendor == "Apache"
        assert product.product == "Log4j"
        assert product.version_exact == "2.14.1"

    def test_affected_product_defaults(self) -> None:
        """Test default values."""
        product = AffectedProduct(vendor="Apache", product="Log4j")
        assert product.version_exact == ""
        assert product.version_start == ""
        assert product.version_end == ""

    def test_matches_version(self) -> None:
        """Test version matching."""
        product = AffectedProduct(
            vendor="Apache",
            product="Log4j",
            version_exact="2.14.1",
        )
        assert product.matches_version("2.14.1") is True
        assert product.matches_version("2.15.0") is False


class TestCVEEntry:
    """Tests for CVEEntry dataclass."""

    def test_create_basic_entry(self) -> None:
        """Test creating a basic CVE entry."""
        entry = CVEEntry(
            id="CVE-2021-44228",
            source=CVESource.NVD,
            description="Apache Log4j2 JNDI RCE vulnerability",
        )
        assert entry.id == "CVE-2021-44228"
        assert entry.source == CVESource.NVD
        assert "Log4j" in entry.description

    def test_create_full_entry(self) -> None:
        """Test creating a fully populated entry."""
        entry = CVEEntry(
            id="CVE-2021-44228",
            source=CVESource.NVD,
            description="Apache Log4j2 JNDI RCE vulnerability",
            cvss=CVSSData(version="3.1", base_score=10.0),
            published_date=datetime(2021, 12, 10),
            last_modified_date=datetime(2021, 12, 15),
            references=[
                CVEReference(url="https://logging.apache.org/log4j/2.x/security.html"),
            ],
            cwe_ids=["CWE-502", "CWE-917"],
            affected_products=[
                AffectedProduct(
                    vendor="Apache", product="Log4j", version_exact="2.14.1"
                ),
            ],
            has_exploit=True,
        )
        assert entry.severity == CVESeverity.CRITICAL
        assert entry.score == 10.0
        assert len(entry.references) == 1
        assert len(entry.cwe_ids) == 2
        assert entry.has_exploit is True

    def test_score_property(self) -> None:
        """Test the score property returns CVSS score."""
        entry = CVEEntry(
            id="CVE-2021-12345",
            source=CVESource.CIRCL,
            description="Test",
            cvss=CVSSData(version="3.1", base_score=7.5),
        )
        assert entry.score == 7.5

    def test_score_property_no_cvss(self) -> None:
        """Test score is None when no CVSS data."""
        entry = CVEEntry(
            id="CVE-2021-12345",
            source=CVESource.CIRCL,
            description="Test",
        )
        assert entry.score is None

    def test_severity_property(self) -> None:
        """Test severity computed from CVSS."""
        entry = CVEEntry(
            id="CVE-2021-12345",
            source=CVESource.NVD,
            description="Test",
            cvss=CVSSData(version="3.1", base_score=8.5),
        )
        assert entry.severity == CVESeverity.HIGH


class TestCVESearchQuery:
    """Tests for CVESearchQuery dataclass."""

    def test_create_simple_query(self) -> None:
        """Test creating a simple search query."""
        query = CVESearchQuery(product="wordpress")
        assert query.product == "wordpress"
        assert query.vendor == ""
        assert query.version == ""

    def test_create_full_query(self) -> None:
        """Test creating a query with all parameters."""
        query = CVESearchQuery(
            vendor="Apache",
            product="Log4j",
            version="2.14.1",
            min_cvss_score=7.0,
            limit=10,
        )
        assert query.vendor == "Apache"
        assert query.product == "Log4j"
        assert query.limit == 10

    def test_to_circl_params(self) -> None:
        """Test conversion to CIRCL API parameters."""
        query = CVESearchQuery(
            vendor="Apache",
            product="Log4j",
        )
        params = query.to_circl_params()
        assert params["vendor"] == "Apache"
        assert params["product"] == "Log4j"


class TestCVESearchResult:
    """Tests for CVESearchResult dataclass."""

    def test_create_empty_result(self) -> None:
        """Test creating an empty search result."""
        result = CVESearchResult(source=CVESource.NVD)
        assert result.source == CVESource.NVD
        assert result.entries == []
        assert result.total_count == 0

    def test_create_result_with_entries(self) -> None:
        """Test creating result with CVE entries."""
        entries = [
            CVEEntry(id="CVE-2021-44228", source=CVESource.NVD, description="Log4j"),
            CVEEntry(id="CVE-2021-45046", source=CVESource.NVD, description="Log4j"),
        ]
        result = CVESearchResult(
            source=CVESource.NVD,
            entries=entries,
            total_count=2,
        )
        assert len(result.entries) == 2
        assert result.total_count == 2
        assert result.has_error is False

    def test_result_with_error(self) -> None:
        """Test creating result with error."""
        result = CVESearchResult(
            source=CVESource.NVD,
            error="API rate limit exceeded",
        )
        assert result.has_error is True
        assert "rate limit" in result.error.lower()


class TestAggregatedCVEResult:
    """Tests for AggregatedCVEResult dataclass."""

    def test_create_empty_aggregated(self) -> None:
        """Test creating an empty aggregated result."""
        result = AggregatedCVEResult()
        assert result.entries == []
        assert result.sources_queried == []
        assert result.sources_succeeded == []
        assert result.sources_failed == {}

    def test_create_full_aggregated(self) -> None:
        """Test creating a fully populated aggregated result."""
        entries = [
            CVEEntry(id="CVE-2021-44228", source=CVESource.NVD, description="Log4j"),
        ]
        result = AggregatedCVEResult(
            entries=entries,
            sources_queried=[CVESource.NVD, CVESource.CIRCL],
            sources_succeeded=[CVESource.NVD],
            sources_failed={CVESource.CIRCL: "Connection timeout"},
            duplicates_removed=3,
            total_query_time_ms=250,
        )
        assert len(result.entries) == 1
        assert len(result.sources_queried) == 2
        assert len(result.sources_succeeded) == 1
        assert CVESource.CIRCL in result.sources_failed
        assert result.duplicates_removed == 3
