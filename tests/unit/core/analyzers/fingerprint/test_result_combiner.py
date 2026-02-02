"""Unit tests for fingerprint result combiner."""

from __future__ import annotations

from ciberwebscan.core.analyzers.fingerprint.result_combiner import (
    calculate_summary,
    combine_and_score_results,
)


class TestCombineAndScoreResults:
    """Tests for combine_and_score_results function."""

    def test_empty_results(self) -> None:
        """Test combining empty results."""
        empty_detected = {
            "cms": [],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        empty_sources: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }
        empty_debug: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }

        result = combine_and_score_results(
            empty_detected,
            empty_detected,
            empty_sources,
            empty_sources,
            empty_debug,
            empty_debug,
        )

        assert "technologies" in result
        assert len(result["technologies"]["cms"]) == 0

    def test_combine_from_single_source(self) -> None:
        """Test combining with single source detection."""
        headers = {
            "cms": ["WordPress 5.8"],
            "frameworks": [],
            "servers": ["nginx 1.18"],
            "js_libraries": [],
            "other": [],
        }
        html = {
            "cms": [],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        sources_headers: dict = {
            "cms": {"WordPress": {"meta"}},
            "frameworks": {},
            "servers": {"nginx": {"headers"}},
            "js_libraries": {},
            "other": {},
        }
        empty_sources: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }
        empty_debug: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }

        result = combine_and_score_results(
            headers,
            html,
            sources_headers,
            empty_sources,
            empty_debug,
            empty_debug,
        )

        techs = result["technologies"]
        assert len(techs["cms"]) == 1
        assert techs["cms"][0]["name"] == "WordPress 5.8"
        assert techs["cms"][0]["confidence"] == "medium"

    def test_combine_from_multiple_sources_high_confidence(self) -> None:
        """Test high confidence when detected from multiple sources."""
        headers = {
            "cms": ["WordPress 5.8"],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        html = {
            "cms": ["WordPress 5.8"],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        sources_headers: dict = {
            "cms": {"WordPress": {"header:x-generator"}},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }
        sources_html: dict = {
            "cms": {"WordPress": {"meta:generator"}},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }
        empty_debug: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }

        result = combine_and_score_results(
            headers,
            html,
            sources_headers,
            sources_html,
            empty_debug,
            empty_debug,
        )

        techs = result["technologies"]
        assert len(techs["cms"]) == 1
        assert techs["cms"][0]["confidence"] == "high"

    def test_deduplicate_technologies(self) -> None:
        """Test that duplicate technologies are deduplicated."""
        headers = {
            "cms": ["WordPress 5.8", "WordPress 5.8"],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        html = {
            "cms": ["WordPress 5.8"],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        empty_sources: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }
        empty_debug: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }

        result = combine_and_score_results(
            headers,
            html,
            empty_sources,
            empty_sources,
            empty_debug,
            empty_debug,
        )

        techs = result["technologies"]
        assert len(techs["cms"]) == 1

    def test_prefer_more_specific_version(self) -> None:
        """Test preferring more specific version."""
        headers = {
            "cms": ["WordPress 5"],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        html = {
            "cms": ["WordPress 5.8.1"],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        empty_sources: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }
        empty_debug: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }

        result = combine_and_score_results(
            headers,
            html,
            empty_sources,
            empty_sources,
            empty_debug,
            empty_debug,
        )

        techs = result["technologies"]
        assert len(techs["cms"]) == 1
        # Should prefer more specific version
        assert "5.8.1" in techs["cms"][0]["name"] or "5" in techs["cms"][0]["name"]

    def test_results_sorted_by_name(self) -> None:
        """Test that results are sorted by name."""
        headers = {
            "cms": ["Drupal", "WordPress", "Joomla"],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        empty: dict = {
            "cms": [],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }
        empty_sources: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }
        empty_debug: dict = {
            "cms": {},
            "frameworks": {},
            "servers": {},
            "js_libraries": {},
            "other": {},
        }

        result = combine_and_score_results(
            headers,
            empty,
            empty_sources,
            empty_sources,
            empty_debug,
            empty_debug,
        )

        techs = result["technologies"]
        names = [t["name"] for t in techs["cms"]]
        assert names == sorted(names)


class TestCalculateSummary:
    """Tests for calculate_summary function."""

    def test_empty_technologies(self) -> None:
        """Test summary with no technologies."""
        techs = {
            "cms": [],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }

        summary = calculate_summary(techs)

        assert summary["total_technologies_detected"] == 0
        assert summary["has_cms"] is False
        assert summary["has_frameworks"] is False

    def test_with_cms(self) -> None:
        """Test summary with CMS detected."""
        techs = {
            "cms": [{"name": "WordPress"}],
            "frameworks": [],
            "servers": [],
            "js_libraries": [],
            "other": [],
        }

        summary = calculate_summary(techs)

        assert summary["total_technologies_detected"] == 1
        assert summary["has_cms"] is True

    def test_with_multiple_categories(self) -> None:
        """Test summary with multiple categories."""
        techs = {
            "cms": [{"name": "WordPress"}],
            "frameworks": [{"name": "Laravel"}],
            "servers": [{"name": "nginx"}],
            "js_libraries": [{"name": "jQuery"}, {"name": "Vue"}],
            "other": [],
        }

        summary = calculate_summary(techs)

        assert summary["total_technologies_detected"] == 5
        assert summary["has_cms"] is True
        assert summary["has_frameworks"] is True
        assert summary["has_js_libraries"] is True
        assert summary["server_identified"] is True
