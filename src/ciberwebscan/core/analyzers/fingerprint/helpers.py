"""
Helper functions for technology fingerprinting.

This module provides utility functions used across the fingerprint package.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any


def get_timestamp() -> str:
    """
    Get the current date and time in ISO 8601 format.

    Returns:
        String with current date and time in ISO 8601 format
        (e.g., '2025-01-31T12:34:56.789012').
    """
    return datetime.now().isoformat()


def append_tech_with_version(
    detected_list: list[str],
    name: str,
    text: str,
    regex: str | None = None,
) -> str:
    """
    Add a technology to the detected list, extracting version if possible.

    Args:
        detected_list: List where the detected technology will be added.
        name: Technology name (e.g., 'WordPress', 'Nginx').
        text: Text where to search for the version.
        regex: Optional regular expression to extract version.
               Must contain a capture group for the version.

    Returns:
        The label that was added (with or without version).
    """
    label = name
    version: str | None = None

    if regex:
        match = re.search(regex, text, re.IGNORECASE)
        if match and match.group(1):
            version = match.group(1).strip(" .-")
            label = f"{name} {version}"

    if not version:
        # Try generic patterns
        generic_patterns = [
            rf"{re.escape(name.lower())}[\s\/-]+(\d+(?:\.\d+)*)",
            r"v(\d+(?:\.\d+)*)",
            r"version[\s\/-]+(\d+(?:\.\d+)*)",
        ]
        for pattern in generic_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match and match.group(1):
                version = match.group(1).strip(" .-")
                label = f"{name} {version}"
                break

    if label not in detected_list:
        detected_list.append(label)

    return label


def append_tech_with_version_debug(
    detected_list: list[str],
    debug_dict: dict[str, Any],
    sources_dict: dict[str, set[str]],
    name: str,
    value: str,
    regex: str | None = None,
    source: str | None = None,
    matched: str | None = None,
) -> str:
    """
    Add a detected technology with version and debug information.

    Args:
        detected_list: List where detected technologies are added.
        debug_dict: Dictionary for debug information.
        sources_dict: Dictionary mapping technology names to detection sources.
        name: Technology name.
        value: Full text where the technology was found.
        regex: Optional regex pattern to extract version.
        source: Detection source identifier.
        matched: Matching text that triggered detection.

    Returns:
        The label that was added.
    """
    label = name
    version: str | None = None

    # Try to extract version with custom regex
    if regex:
        match_obj = re.search(regex, value, re.IGNORECASE)
        if match_obj and match_obj.group(1):
            version = match_obj.group(1)
            label = f"{name} {version}"

    # Try generic patterns if no version found
    if version is None:
        generic_patterns = [
            rf"{re.escape(name.lower())}[\s\/-]+(\d+(?:\.\d+)*)",
            r"v(\d+(?:\.\d+)*)",
            r"version[\s\/-]+(\d+(?:\.\d+)*)",
            r"(\d+(?:\.\d+)*)",
        ]

        for pattern in generic_patterns:
            match_obj = re.search(pattern, value, re.IGNORECASE)
            if match_obj and match_obj.group(1):
                version = match_obj.group(1)
                label = f"{name} {version}"
                break

    # Add to detected list if not already present
    if label not in detected_list:
        detected_list.append(label)

    # Update debug info
    debug_dict[name] = {
        "matched": matched or value,
        "source": source or "unknown",
        "version": version,
    }

    # Update sources
    if name not in sources_dict:
        sources_dict[name] = set()
    if source:
        sources_dict[name].add(source)

    return label


def normalize_technology_name(name: str) -> str:
    """
    Normalize a technology name for consistent comparison.

    Args:
        name: Technology name to normalize.

    Returns:
        Normalized technology name.
    """
    return name.lower().strip()


def extract_version_from_string(text: str, tech_name: str | None = None) -> str | None:
    """
    Extract a version string from text.

    Args:
        text: Text to search for version.
        tech_name: Optional technology name to aid extraction.

    Returns:
        Version string or None if not found.
    """
    patterns = []

    if tech_name:
        patterns.append(rf"{re.escape(tech_name)}[\s\/-]+(\d+(?:\.\d+)*)")

    patterns.extend(
        [
            r"v(\d+(?:\.\d+)+)",
            r"version[\s\/-]+(\d+(?:\.\d+)*)",
            r"/(\d+\.\d+(?:\.\d+)*)/",
            r"@(\d+\.\d+(?:\.\d+)*)",
        ]
    )

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)

    return None
