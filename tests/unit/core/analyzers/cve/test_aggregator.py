"""
Unit tests for CVE aggregator.

Tests the aggregation logic that combines results from multiple CVE sources.
"""

from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

from ciberwebscan.core.analyzers.cve.aggregator import CVEAggregator, lookup_cves
from ciberwebscan.core.analyzers.cve.models import (
    CVEEntry,
    CVEReference,
    CVESearchResult,
    CVESource,
    CVSSData,
)


class TestCVEAggregator:
    """Tests for CVEAggregator class."""

    def test_init_default_sources(self) -> None:
        """Test default sources are NVD and CIRCL."""
        aggregator = CVEAggregator()
        assert CVESource.NVD in aggregator.sources
        assert CVESource.CIRCL in aggregator.sources

    def test_init_custom_sources(self) -> None:
        """Test initialization with custom sources."""
        aggregator = CVEAggregator(sources=[CVESource.VULNERS])
        assert aggregator.sources == [CVESource.VULNERS]

    @patch.object(CVEAggregator, "_query_source")
    def test_search_basic(self, mock_query: Mock) -> None:
        """Test basic search aggregation."""
        # Mock results from sources
        mock_query.side_effect = [
            CVESearchResult(
                source=CVESource.NVD,
                entries=[
                    CVEEntry(
                        id="CVE-2021-44228",
                        source=CVESource.NVD,
                        description="Log4j RCE",
                        cvss=CVSSData(version="3.1", base_score=10.0),
                    ),
                ],
            ),
            CVESearchResult(
                source=CVESource.CIRCL,
                entries=[
                    CVEEntry(
                        id="CVE-2021-45046",
                        source=CVESource.CIRCL,
                        description="Log4j incomplete fix",
                        cvss=CVSSData(version="3.1", base_score=9.0),
                    ),
                ],
            ),
        ]

        aggregator = CVEAggregator()
        result = aggregator.search("log4j")

        assert len(result.entries) == 2
        assert len(result.sources_succeeded) == 2
        assert result.duplicates_removed == 0

    @patch.object(CVEAggregator, "_query_source")
    def test_search_deduplication(self, mock_query: Mock) -> None:
        """Test deduplication of entries from multiple sources."""
        # Same CVE from multiple sources
        mock_query.side_effect = [
            CVESearchResult(
                source=CVESource.NVD,
                entries=[
                    CVEEntry(
                        id="CVE-2021-44228",
                        source=CVESource.NVD,
                        description="Short description",
                    ),
                ],
            ),
            CVESearchResult(
                source=CVESource.CIRCL,
                entries=[
                    CVEEntry(
                        id="CVE-2021-44228",  # Duplicate
                        source=CVESource.CIRCL,
                        description="Much longer and more detailed description of the vulnerability",
                    ),
                ],
            ),
        ]

        aggregator = CVEAggregator()
        result = aggregator.search("log4j")

        assert len(result.entries) == 1
        assert result.duplicates_removed == 1
        # Longer description should be kept
        assert "longer" in result.entries[0].description

    @patch.object(CVEAggregator, "_query_source")
    def test_search_merge_references(self, mock_query: Mock) -> None:
        """Test merging references from duplicate entries."""
        mock_query.side_effect = [
            CVESearchResult(
                source=CVESource.NVD,
                entries=[
                    CVEEntry(
                        id="CVE-2021-44228",
                        source=CVESource.NVD,
                        description="Test",
                        references=[
                            CVEReference(
                                url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                            ),
                        ],
                    ),
                ],
            ),
            CVESearchResult(
                source=CVESource.CIRCL,
                entries=[
                    CVEEntry(
                        id="CVE-2021-44228",
                        source=CVESource.CIRCL,
                        description="Test",
                        references=[
                            CVEReference(
                                url="https://logging.apache.org/log4j/2.x/security.html"
                            ),
                        ],
                    ),
                ],
            ),
        ]

        aggregator = CVEAggregator()
        result = aggregator.search("log4j")

        assert len(result.entries) == 1
        assert len(result.entries[0].references) == 2

    @patch.object(CVEAggregator, "_query_source")
    def test_search_source_failure(self, mock_query: Mock) -> None:
        """Test handling of source failure."""
        mock_query.side_effect = [
            CVESearchResult(
                source=CVESource.NVD,
                entries=[
                    CVEEntry(
                        id="CVE-2021-44228",
                        source=CVESource.NVD,
                        description="Test",
                    ),
                ],
            ),
            CVESearchResult(
                source=CVESource.CIRCL,
                error="Connection timeout",
            ),
        ]

        aggregator = CVEAggregator()
        result = aggregator.search("test")

        assert len(result.entries) == 1
        assert CVESource.NVD in result.sources_succeeded
        assert CVESource.CIRCL in result.sources_failed
        assert "timeout" in result.sources_failed[CVESource.CIRCL]

    @patch.object(CVEAggregator, "_query_source")
    def test_search_with_source_override(self, mock_query: Mock) -> None:
        """Test overriding default sources for a single query."""
        mock_query.return_value = CVESearchResult(
            source=CVESource.VULNERS,
            entries=[],
        )

        aggregator = CVEAggregator()  # Default: NVD, CIRCL
        aggregator.search("test", sources=[CVESource.VULNERS])

        # Should only query VULNERS
        mock_query.assert_called_once()
        call_args = mock_query.call_args[0]
        assert call_args[0] == CVESource.VULNERS


class TestLookupCVEs:
    """Tests for the convenience function."""

    @patch.object(CVEAggregator, "search")
    def test_lookup_cves_basic(self, mock_search: Mock) -> None:
        """Test basic usage of convenience function."""
        mock_search.return_value = MagicMock(
            entries=[
                CVEEntry(
                    id="CVE-2021-44228",
                    source=CVESource.NVD,
                    description="Log4j",
                    cvss=CVSSData(version="3.1", base_score=10.0),
                    published_date=datetime(2021, 12, 10),
                    references=[CVEReference(url="https://example.com")],
                    cwe_ids=["CWE-502"],
                    has_exploit=True,
                ),
            ],
        )

        result = lookup_cves("log4j")

        assert len(result) == 1
        assert result[0]["id"] == "CVE-2021-44228"
        assert result[0]["has_exploit"] is True

    @patch.object(CVEAggregator, "search")
    def test_lookup_cves_with_sources(self, mock_search: Mock) -> None:
        """Test lookup with specific sources."""
        mock_search.return_value = MagicMock(entries=[])

        lookup_cves("test", sources=["nvd", "circl"])

        mock_search.assert_called_once()
        call_kwargs = mock_search.call_args[1]
        assert CVESource.NVD in call_kwargs["sources"]
        assert CVESource.CIRCL in call_kwargs["sources"]


class TestCVEAggregatorConfigParams:
    """Tests for config-driven CVEAggregator parameters."""

    def test_default_cache_ttl(self) -> None:
        """Test default cache_ttl value."""
        aggregator = CVEAggregator()
        assert aggregator.cache_ttl == 86400

    def test_custom_cache_ttl(self) -> None:
        """Test initialization with custom cache_ttl."""
        aggregator = CVEAggregator(cache_ttl=3600)
        assert aggregator.cache_ttl == 3600

    @patch.dict("os.environ", {"NVD_API_KEY": "", "VULNERS_API_KEY": ""})
    def test_custom_api_keys(self) -> None:
        """Test initialization with API keys."""
        aggregator = CVEAggregator(
            nvd_api_key="test-nvd-key",
            vulners_api_key="test-vulners-key",
        )
        assert aggregator.nvd_client.api_key == "test-nvd-key"
        assert aggregator.vulners_client.api_key == "test-vulners-key"
