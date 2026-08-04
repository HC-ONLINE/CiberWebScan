"""
Technology fingerprinting module.

This module provides functionality for detecting web technologies
(CMS, frameworks, servers, JavaScript libraries) through HTTP header
and HTML content analysis.
"""

from __future__ import annotations

from .header_analyzer import analyze_headers
from .helpers import (
    append_tech_with_version,
    append_tech_with_version_debug,
    extract_version_from_string,
    get_timestamp,
    normalize_technology_name,
)
from .html_analyzer import analyze_html_content
from .orchestrator import TechnologyFingerprinter, fingerprint_technologies
from .result_combiner import calculate_summary, combine_and_score_results
from .signature_loader import (
    TechnologySignatures,
    clear_signatures_cache,
    get_default_signatures_path,
    get_signature_categories,
    load_technology_signatures,
)

__all__ = [
    # Main class
    "TechnologyFingerprinter",
    # Convenience functions
    "fingerprint_technologies",
    # Analyzers
    "analyze_headers",
    "analyze_html_content",
    # Combiners
    "combine_and_score_results",
    "calculate_summary",
    # Signature loading
    "load_technology_signatures",
    "clear_signatures_cache",
    "get_default_signatures_path",
    "get_signature_categories",
    "TechnologySignatures",
    # Helpers
    "get_timestamp",
    "append_tech_with_version",
    "append_tech_with_version_debug",
    "normalize_technology_name",
    "extract_version_from_string",
]
