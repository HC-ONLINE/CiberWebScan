"""
Technology fingerprinting orchestrator.

This module provides the main TechnologyFingerprinter class that coordinates
the complete web technology detection process, combining HTTP header analysis,
HTML content analysis, and CVE lookup.
"""

from __future__ import annotations

import logging
from typing import Any

from .header_analyzer import analyze_headers
from .helpers import get_timestamp
from .html_analyzer import analyze_html_content
from .result_combiner import calculate_summary, combine_and_score_results
from .signature_loader import load_technology_signatures

logger = logging.getLogger(__name__)


class TechnologyFingerprinter:
    """
    Main class for web technology detection via fingerprinting.

    This class coordinates the complete technology detection process, including:
    - HTTP header analysis
    - HTML content analysis
    - Known technology signature matching
    - Related CVE lookup (optional)

    Attributes:
        cms_signatures: Content management system signatures.
        framework_signatures: Web framework signatures.
        server_signatures: Web server signatures.
        js_library_signatures: JavaScript library signatures.
    """

    def __init__(self, signatures_path: str | None = None) -> None:
        """
        Initialize the fingerprinter by loading technology signatures.

        Args:
            signatures_path: Optional path to signatures file.
                           If None, uses the default path.
        """
        signatures = load_technology_signatures(signatures_path)
        self.cms_signatures = signatures.get("cms_signatures", {})
        self.framework_signatures = signatures.get("framework_signatures", {})
        self.server_signatures = signatures.get("server_signatures", {})
        self.js_library_signatures = signatures.get("js_library_signatures", {})

        logger.debug(
            "TechnologyFingerprinter initialized with %d CMS, %d framework, "
            "%d server, %d JS library signatures",
            len(self.cms_signatures),
            len(self.framework_signatures),
            len(self.server_signatures),
            len(self.js_library_signatures),
        )

    def fingerprint(
        self,
        headers: dict[str, str],
        html_content: str,
        debug: bool = False,
    ) -> dict[str, Any]:
        """
        Perform complete technology fingerprinting analysis.

        This method coordinates the entire detection process:
        1. HTTP header analysis
        2. HTML content analysis
        3. Result combination and scoring

        Args:
            headers: Dictionary with HTTP response headers.
            html_content: HTML content of the analyzed page.
            debug: If True, includes detailed debug info in response.

        Returns:
            Dictionary with fingerprinting results.
        """
        logger.info("Starting technology fingerprinting analysis")

        # Analyze headers
        header_results = analyze_headers(
            headers,
            self.cms_signatures,
            self.framework_signatures,
            self.server_signatures,
            debug_enabled=debug,
        )
        detected_headers = header_results["detected_headers"]
        debug_info_headers = header_results["debug_info"]
        sources_info_headers = header_results["sources_info"]

        # Analyze HTML
        html_results = analyze_html_content(
            html_content,
            self.cms_signatures,
            self.framework_signatures,
            self.js_library_signatures,
            debug_enabled=debug,
        )
        detected_html = html_results["detected_html"]
        debug_info_html = html_results["debug_info"]
        sources_info_html = html_results["sources_info"]

        # Combine results and calculate confidence
        combined_data = combine_and_score_results(
            detected_headers,
            detected_html,
            sources_info_headers,
            sources_info_html,
            debug_info_headers,
            debug_info_html,
            debug_enabled=debug,
        )
        combined_technologies = combined_data["technologies"]
        final_debug_info = combined_data["debug_info"]

        # Calculate summary
        summary = calculate_summary(combined_technologies)

        result: dict[str, Any] = {
            "technologies": combined_technologies,
            "summary": summary,
            "analysis_timestamp": get_timestamp(),
        }

        # Attach debug info if enabled
        if debug:
            for key, value in final_debug_info.items():
                result[f"_{key}_debug"] = value

        logger.info(
            "Fingerprinting completed. Total technologies detected: %d",
            summary["total_technologies_detected"],
        )

        return result

    def get_technology_list(
        self,
        headers: dict[str, str],
        html_content: str,
    ) -> list[str]:
        """
        Get a flat list of detected technologies.

        This is a convenience method that returns just the technology names
        without categories or confidence levels.

        Args:
            headers: Dictionary with HTTP response headers.
            html_content: HTML content of the analyzed page.

        Returns:
            List of detected technology names.
        """
        result = self.fingerprint(headers, html_content, debug=False)
        technologies: list[str] = []

        for category_techs in result["technologies"].values():
            for tech in category_techs:
                if isinstance(tech, dict) and "name" in tech:
                    technologies.append(tech["name"])
                elif isinstance(tech, str):
                    technologies.append(tech)

        return technologies

    def get_technologies_by_category(
        self,
        headers: dict[str, str],
        html_content: str,
    ) -> dict[str, list[str]]:
        """
        Get detected technologies grouped by category.

        Args:
            headers: Dictionary with HTTP response headers.
            html_content: HTML content of the analyzed page.

        Returns:
            Dictionary with technology names grouped by category.
        """
        result = self.fingerprint(headers, html_content, debug=False)
        categorized: dict[str, list[str]] = {}

        for category, techs in result["technologies"].items():
            categorized[category] = []
            for tech in techs:
                if isinstance(tech, dict) and "name" in tech:
                    categorized[category].append(tech["name"])
                elif isinstance(tech, str):
                    categorized[category].append(tech)

        return categorized


def fingerprint_technologies(
    headers: dict[str, str],
    html_content: str,
    debug: bool = False,
    signatures_path: str | None = None,
) -> dict[str, Any]:
    """
    Convenience function for technology fingerprinting.

    Args:
        headers: Dictionary with HTTP response headers.
        html_content: HTML content of the analyzed page.
        debug: If True, includes detailed debug info.
        signatures_path: Optional path to signatures file.

    Returns:
        Dictionary with fingerprinting results.
    """
    fingerprinter = TechnologyFingerprinter(signatures_path)
    return fingerprinter.fingerprint(headers, html_content, debug)
