"""
HTML content analyzer for technology detection.

This module provides functionality to analyze HTML content and detect
technologies like CMS, frameworks, and JavaScript libraries based on
specific patterns in the HTML code, meta tags, scripts, and styles.
"""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup, Tag

from ciberwebscan.core.analyzers.fingerprint import append_tech_with_version_debug


def analyze_html_content(
    html_content: str,
    cms_signatures: dict[str, Any],
    framework_signatures: dict[str, Any],
    js_library_signatures: dict[str, Any],
    debug_enabled: bool = False,
) -> dict[str, Any]:
    """
    Analyze HTML content to detect web technologies used.

    This function examines HTML content for patterns that indicate
    the use of CMS, frameworks, and JavaScript libraries.

    Args:
        html_content: Complete HTML content to analyze.
        cms_signatures: CMS detection signatures.
        framework_signatures: Framework detection signatures.
        js_library_signatures: JavaScript library detection signatures.
        debug_enabled: If True, includes detailed debug info in results.

    Returns:
        Dictionary containing:
        - 'detected_html': Technologies detected grouped by category.
        - 'debug_info': Debug information if enabled.
        - 'sources_info': Mapping of technologies to detection sources.
    """
    detected_html: dict[str, list[str]] = {
        "cms": [],
        "frameworks": [],
        "servers": [],
        "js_libraries": [],
        "other": [],
    }
    debug_info: dict[str, dict[str, Any]] = {
        "cms": {},
        "frameworks": {},
        "servers": {},
        "js_libraries": {},
        "other": {},
    }
    sources_info: dict[str, dict[str, set[str]]] = {
        "cms": {},
        "frameworks": {},
        "servers": {},
        "js_libraries": {},
        "other": {},
    }

    soup = BeautifulSoup(html_content, "html.parser")
    content_lower = html_content.lower()

    # Detect CMS from meta generator tag
    meta_generator = soup.find("meta", attrs={"name": "generator"})
    if isinstance(meta_generator, Tag):
        content = meta_generator.get("content")
        if content:
            generator_content = str(content)
            for cms_name in cms_signatures:
                if cms_name.lower() in generator_content.lower():
                    regex = rf"{cms_name.lower()}[\s\/-]+([\d\.]+)"
                    append_tech_with_version_debug(
                        detected_html["cms"],
                        debug_info["cms"],
                        sources_info["cms"],
                        cms_name,
                        generator_content,
                        regex,
                        source="meta",
                        matched=f"meta:generator={generator_content}",
                    )
                    break

    # Analyze additional meta tags
    for meta in soup.find_all("meta"):
        if not isinstance(meta, Tag):
            continue

        meta_name = str(meta.get("name", "")).lower()
        meta_content = str(meta.get("content", ""))
        if not meta_content:
            continue

        # Search in CMS signatures
        for cms_name in cms_signatures:
            if cms_name.lower() in meta_content.lower() and meta_name != "generator":
                regex = rf"{cms_name.lower()}[\s\/-]+([\d\.]+)"
                append_tech_with_version_debug(
                    detected_html["cms"],
                    debug_info["cms"],
                    sources_info["cms"],
                    cms_name,
                    meta_content,
                    regex,
                    source=f"meta:{meta_name}",
                    matched=f"meta:{meta_name}={meta_content}",
                )

        # Search in framework signatures
        for fw_name in framework_signatures:
            if fw_name.lower() in meta_content.lower():
                escaped = fw_name.lower().replace(".", r"\.")
                regex = rf"{escaped}[\s\/-]+([\d\.]+)"
                append_tech_with_version_debug(
                    detected_html["frameworks"],
                    debug_info["frameworks"],
                    sources_info["frameworks"],
                    fw_name,
                    meta_content,
                    regex,
                    source=f"meta:{meta_name}",
                    matched=f"meta:{meta_name}={meta_content}",
                )

    # Detect CMS by content patterns
    for cms_name, signatures in cms_signatures.items():
        for pattern in signatures.get("content_patterns", []):
            match = re.search(pattern + r"[\/-]?([\d\.]+)?", content_lower)
            if match:
                version = (
                    match.group(1) if match.lastindex and match.lastindex >= 1 else None
                )
                label = f"{cms_name} {version}" if version else cms_name
                if label not in detected_html["cms"]:
                    detected_html["cms"].append(label)
                    if debug_enabled:
                        debug_info["cms"][cms_name] = {
                            "matched": f"content_pattern:{pattern}",
                            "source": "html_content",
                        }
                    if cms_name not in sources_info["cms"]:
                        sources_info["cms"][cms_name] = set()
                    sources_info["cms"][cms_name].add("html_content")
                break

    # Detect frameworks by content patterns
    for fw_name, signatures in framework_signatures.items():
        for pattern in signatures.get("content_patterns", []):
            match = re.search(pattern + r"[\/-]?([\d\.]+)?", content_lower)
            if match:
                version = (
                    match.group(1) if match.lastindex and match.lastindex >= 1 else None
                )
                label = f"{fw_name} {version}" if version else fw_name
                if label not in detected_html["frameworks"]:
                    detected_html["frameworks"].append(label)
                    if debug_enabled:
                        debug_info["frameworks"][fw_name] = {
                            "matched": f"content_pattern:{pattern}",
                            "source": "html_content",
                        }
                    if fw_name not in sources_info["frameworks"]:
                        sources_info["frameworks"][fw_name] = set()
                    sources_info["frameworks"][fw_name].add("html_content")
                break

    # Analyze scripts for JavaScript libraries
    for script in soup.find_all("script"):
        if not isinstance(script, Tag):
            continue

        src = str(script.get("src", ""))
        if not src:
            continue

        for lib_name, signatures in js_library_signatures.items():
            for pattern in signatures.get("script_patterns", []):
                match = re.search(pattern + r"[\/-]?([\d\.]+)?", src, re.IGNORECASE)
                if match:
                    version = (
                        match.group(1)
                        if match.lastindex and match.lastindex >= 1
                        else None
                    )
                    label = f"{lib_name} {version}" if version else lib_name
                    if label not in detected_html["js_libraries"]:
                        detected_html["js_libraries"].append(label)
                        if debug_enabled:
                            debug_info["js_libraries"][lib_name] = {
                                "matched": f"script:src={src}",
                                "source": "script",
                            }
                        if lib_name not in sources_info["js_libraries"]:
                            sources_info["js_libraries"][lib_name] = set()
                        sources_info["js_libraries"][lib_name].add("script")
                    break

    # Analyze CSS links
    for link in soup.find_all("link", rel="stylesheet"):
        if not isinstance(link, Tag):
            continue

        href = str(link.get("href", ""))
        if not href:
            continue

        for lib_name, signatures in js_library_signatures.items():
            for pattern in signatures.get("css_patterns", []):
                match = re.search(pattern + r"[\/-]?([\d\.]+)?", href, re.IGNORECASE)
                if match:
                    version = (
                        match.group(1)
                        if match.lastindex and match.lastindex >= 1
                        else None
                    )
                    label = f"{lib_name} {version}" if version else lib_name
                    if label not in detected_html["js_libraries"]:
                        detected_html["js_libraries"].append(label)
                        if debug_enabled:
                            debug_info["js_libraries"][lib_name] = {
                                "matched": f"css:href={href}",
                                "source": "css",
                            }
                        if lib_name not in sources_info["js_libraries"]:
                            sources_info["js_libraries"][lib_name] = set()
                        sources_info["js_libraries"][lib_name].add("css")
                    break

    # Detect PHP
    if ("<?php" in html_content or ".php" in content_lower) and (
        "PHP" not in detected_html["other"]
    ):
        detected_html["other"].append("PHP")
        if debug_enabled:
            debug_info["other"]["PHP"] = {
                "matched": "php extension or tag",
                "source": "html_content",
            }

    # Detect CDNs
    if "cdnjs.cloudflare.com" in content_lower and (
        "Cloudflare CDN" not in detected_html["other"]
    ):
        detected_html["other"].append("Cloudflare CDN")
        if debug_enabled:
            debug_info["other"]["Cloudflare CDN"] = {
                "matched": "cdnjs.cloudflare.com",
                "source": "html_content",
            }

    if "ajax.googleapis.com" in content_lower and (
        "Google CDN" not in detected_html["other"]
    ):
        detected_html["other"].append("Google CDN")
        if debug_enabled:
            debug_info["other"]["Google CDN"] = {
                "matched": "ajax.googleapis.com",
                "source": "html_content",
            }

    # Sort results
    for category in detected_html:
        detected_html[category].sort()

    return {
        "detected_html": detected_html,
        "debug_info": debug_info,
        "sources_info": sources_info,
    }
