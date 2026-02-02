"""
Result combiner for technology fingerprinting.

This module provides functionality to combine results from multiple
analysis sources (HTTP headers, HTML content) and calculate confidence
levels for each detected technology.
"""

from __future__ import annotations

from typing import Any


def combine_and_score_results(
    detected_headers: dict[str, list[str]],
    detected_html: dict[str, list[str]],
    sources_info_headers: dict[str, dict[str, set[str]]],
    sources_info_html: dict[str, dict[str, set[str]]],
    debug_info_headers: dict[str, dict[str, Any]],
    debug_info_html: dict[str, dict[str, Any]],
    debug_enabled: bool = False,
) -> dict[str, Any]:
    """
    Combine results from header and HTML analysis, and calculate confidence.

    This function takes results from HTTP header and HTML content analysis,
    combines them, resolves conflicts, and calculates a confidence level
    for each detected technology.

    Args:
        detected_headers: Technologies detected from HTTP headers.
        detected_html: Technologies detected from HTML content.
        sources_info_headers: Detection sources for header technologies.
        sources_info_html: Detection sources for HTML technologies.
        debug_info_headers: Debug information from header analysis.
        debug_info_html: Debug information from HTML analysis.
        debug_enabled: If True, includes debug info in results.

    Returns:
        Dictionary containing:
        - 'technologies': Combined technologies by category.
        - 'debug_info': Combined debug information.
    """
    combined_results: dict[str, list[dict[str, Any]]] = {}
    final_debug_info: dict[str, dict[str, Any]] = {
        "cms": {},
        "frameworks": {},
        "servers": {},
        "js_libraries": {},
        "other": {},
    }

    categories = ["cms", "frameworks", "servers", "js_libraries", "other"]

    for category in categories:
        # Deduplicate technologies by (name, version) tuple
        all_labels: list[str] = []
        seen: set[tuple[str, str | None]] = set()

        header_list = detected_headers.get(category, [])
        html_list = detected_html.get(category, [])

        for label in header_list + html_list:
            if isinstance(label, dict):
                label_dict: dict[str, Any] = label
                key = (label_dict.get("name", ""), label_dict.get("version"))
            elif isinstance(label, str):
                parts = label.split(" ", 1)
                key = (parts[0], parts[1] if len(parts) > 1 else None)
            else:
                key = (str(label), None)

            if key not in seen:
                seen.add(key)
                all_labels.append(label if isinstance(label, str) else str(label))

        # Combine sources
        combined_sources_for_cat: dict[str, set[str]] = {}

        header_sources = sources_info_headers.get(category, {})
        html_sources = sources_info_html.get(category, {})

        for tech_name, sources in header_sources.items():
            combined_sources_for_cat[tech_name] = sources.copy()

        for tech_name, sources in html_sources.items():
            if tech_name not in combined_sources_for_cat:
                combined_sources_for_cat[tech_name] = set()
            combined_sources_for_cat[tech_name].update(sources)

        # Combine debug info
        combined_debug_for_cat: dict[str, Any] = {}
        if debug_enabled:
            combined_debug_for_cat.update(debug_info_html.get(category, {}))
            combined_debug_for_cat.update(debug_info_headers.get(category, {}))

        # Group labels by base name and select best version
        labels_by_base: dict[str, dict[str, Any]] = {}

        for label in all_labels:
            if isinstance(label, str):
                parts = label.split(" ", 1)
                base_name = parts[0]
                version = parts[1] if len(parts) > 1 else None
            else:
                base_name = str(label)
                version = None

            if base_name not in labels_by_base:
                labels_by_base[base_name] = {"label": label, "version": version}
            elif version is not None:
                current = labels_by_base[base_name]
                if current["version"] is None:
                    labels_by_base[base_name] = {"label": label, "version": version}
                elif current["version"] is not None:
                    # Compare versions, prefer more specific
                    try:
                        current_parts = [int(p) for p in current["version"].split(".")]
                        new_parts = [int(p) for p in version.split(".")]

                        if (
                            len(new_parts) > len(current_parts)
                            or len(new_parts) == len(current_parts)
                            and new_parts > current_parts
                        ):
                            labels_by_base[base_name] = {
                                "label": label,
                                "version": version,
                            }
                    except (ValueError, IndexError):
                        pass

        # Calculate confidence levels
        techs_with_conf: list[dict[str, Any]] = []

        for base_name, info in labels_by_base.items():
            sources = combined_sources_for_cat.get(base_name, set())

            if len(sources) >= 2:
                confidence = "high"
            elif len(sources) == 1:
                confidence = "medium"
            else:
                confidence = "low"

            techs_with_conf.append(
                {
                    "name": info["label"],
                    "confidence": confidence,
                }
            )

            if debug_enabled and base_name in combined_debug_for_cat:
                final_debug_info[category][base_name] = combined_debug_for_cat[
                    base_name
                ]
                final_debug_info[category][base_name]["confidence"] = confidence
                final_debug_info[category][base_name]["sources"] = list(sources)

        # Sort by name
        techs_with_conf.sort(key=lambda x: str(x["name"]))
        combined_results[category] = techs_with_conf

    return {
        "technologies": combined_results,
        "debug_info": final_debug_info,
    }


def calculate_summary(technologies: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """
    Calculate summary statistics for detected technologies.

    Args:
        technologies: Technologies grouped by category.

    Returns:
        Summary dictionary with counts and flags.
    """
    total = sum(len(techs) for techs in technologies.values())

    return {
        "total_technologies_detected": total,
        "has_cms": len(technologies.get("cms", [])) > 0,
        "has_frameworks": len(technologies.get("frameworks", [])) > 0,
        "has_js_libraries": len(technologies.get("js_libraries", [])) > 0,
        "server_identified": len(technologies.get("servers", [])) > 0,
    }
