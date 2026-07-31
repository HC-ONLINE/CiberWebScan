"""
HTML content analyzer for technology detection.

This module provides functionality to analyze HTML content and detect
technologies like CMS, frameworks, and JavaScript libraries based on
specific patterns in the HTML code, meta tags, scripts, and styles.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag

from ciberwebscan.core.analyzers.fingerprint import append_tech_with_version_debug

logger = logging.getLogger(__name__)

# CDN URL patterns: hostname -> (library_path_pattern, version_group_index)
# Patterns match the path structure of CDN URLs to extract library name + version
CDN_URL_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "cdnjs.cloudflare.com": [
        re.compile(
            r"/ajax/libs/(?P<lib>[^/]+)/(?P<ver>[^/]+)/",
            re.IGNORECASE,
        ),
    ],
    "cdn.jsdelivr.net": [
        re.compile(
            r"/npm/(?P<lib>[^@/]+)@(?P<ver>[^/]+)/",
            re.IGNORECASE,
        ),
        re.compile(
            r"/gh/(?P<lib>[^@/]+)@(?P<ver>[^/]+)/",
            re.IGNORECASE,
        ),
    ],
    "unpkg.com": [
        re.compile(
            r"/(?P<lib>[^@/]+)@(?P<ver>[^/]+)/",
            re.IGNORECASE,
        ),
    ],
    "ajax.googleapis.com": [
        re.compile(
            r"/ajax/libs/(?P<lib>[^/]+)/(?P<ver>[^/]+)/",
            re.IGNORECASE,
        ),
    ],
    "cdn.bootcdn.net": [
        re.compile(
            r"/ajax/libs/(?P<lib>[^/]+)/(?P<ver>[^/]+)/",
            re.IGNORECASE,
        ),
    ],
    "cdn.staticfile.org": [
        re.compile(
            r"/ajax/libs/(?P<lib>[^/]+)/(?P<ver>[^/]+)/",
            re.IGNORECASE,
        ),
    ],
}

# Known CDN hostnames for detection (substring match on full HTML)
CDN_HOSTNAMES: dict[str, str] = {
    "cdnjs.cloudflare.com": "Cloudflare CDN",
    "ajax.googleapis.com": "Google CDN",
    "cdn.jsdelivr.net": "jsDelivr CDN",
    "unpkg.com": "unpkg CDN",
    "cdn.bootstrapcdn.com": "BootstrapCDN",
    "fastly.net": "Fastly CDN",
    "cdn.cloudflare.com": "Cloudflare CDN",
    "code.jquery.com": "jQuery CDN",
    "ajax.aspnetcdn.com": "Microsoft CDN",
    "cdn.jsdelivr.net/npm": "jsDelivr CDN",
}


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
                match = re.search(pattern + r"[/@-]?([\d\.]+)?", src, re.IGNORECASE)
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

        # Also try structured CDN URL parsing for this script src
        _parse_cdn_url(
            src,
            detected_html["js_libraries"],
            debug_info["js_libraries"] if debug_enabled else None,
            sources_info["js_libraries"],
            "script",
        )

    # Analyze CSS links
    for link in soup.find_all("link", rel="stylesheet"):
        if not isinstance(link, Tag):
            continue

        href = str(link.get("href", ""))
        if not href:
            continue

        for lib_name, signatures in js_library_signatures.items():
            for pattern in signatures.get("css_patterns", []):
                match = re.search(pattern + r"[/@-]?([\d\.]+)?", href, re.IGNORECASE)
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

        # Also try structured CDN URL parsing for this CSS href
        _parse_cdn_url(
            href,
            detected_html["js_libraries"],
            debug_info["js_libraries"] if debug_enabled else None,
            sources_info["js_libraries"],
            "css",
        )

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
    for hostname, cdn_name in CDN_HOSTNAMES.items():
        if hostname in content_lower and cdn_name not in detected_html["other"]:
            detected_html["other"].append(cdn_name)
            if debug_enabled:
                debug_info["other"][cdn_name] = {
                    "matched": hostname,
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


def _parse_cdn_url(
    url: str,
    detected_list: list[str],
    debug_dict: dict[str, Any] | None,
    sources_dict: dict[str, set[str]],
    source_type: str,
) -> None:
    """Extract library name + version from structured CDN URL patterns.

    Handles URL structures like:
    - cdnjs: /ajax/libs/jquery/3.6.0/jquery.min.js
    - jsDelivr: /npm/jquery@3.6.0/dist/jquery.min.js
    - unpkg: /jquery@3.6.0/dist/jquery.min.js
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return

    patterns = CDN_URL_PATTERNS.get(hostname, [])
    for pattern in patterns:
        match = pattern.search(parsed.path)
        if match:
            lib_name = match.group("lib")
            version = match.group("ver")
            label = f"{lib_name} {version}" if version else lib_name
            if label not in detected_list:
                detected_list.append(label)
                if debug_dict is not None:
                    debug_dict[lib_name] = {
                        "matched": f"cdn_url:{url}",
                        "source": source_type,
                    }
                if lib_name not in sources_dict:
                    sources_dict[lib_name] = set()
                sources_dict[lib_name].add(source_type)
            break
