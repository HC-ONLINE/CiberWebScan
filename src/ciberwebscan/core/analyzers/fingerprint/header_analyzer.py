"""
HTTP header analyzer for technology detection.

This module provides functionality to analyze HTTP headers and detect
technologies like CMS, frameworks, and web servers based on specific patterns.
"""

from __future__ import annotations

import re
from typing import Any

from .helpers import append_tech_with_version_debug


def analyze_headers(
    headers: dict[str, str],
    cms_signatures: dict[str, Any],
    framework_signatures: dict[str, Any],
    server_signatures: dict[str, Any],
    debug_enabled: bool = False,
) -> dict[str, Any]:
    """
    Analyze HTTP headers to detect web technologies used.

    This function examines HTTP headers for patterns that indicate
    the use of CMS, frameworks, web servers, and other technologies.

    Args:
        headers: Dictionary of HTTP headers to analyze.
        cms_signatures: CMS detection signatures.
        framework_signatures: Framework detection signatures.
        server_signatures: Web server detection signatures.
        debug_enabled: If True, includes detailed debug info in results.

    Returns:
        Dictionary containing:
        - 'detected_headers': Technologies detected grouped by category.
        - 'debug_info': Debug information if enabled.
        - 'sources_info': Mapping of technologies to detection sources.
    """
    detected_headers: dict[str, list[str]] = {
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

    normalized_headers = {k.lower(): v for k, v in headers.items()}

    # Detect CMS from headers
    for name, signatures in cms_signatures.items():
        for key, value_pattern in signatures.get("headers", []):
            header_value = normalized_headers.get(key)
            if header_value and (
                not value_pattern
                or re.search(value_pattern, header_value, re.IGNORECASE)
            ):
                regex = rf"{name.lower()}[\s\/-]+([\d\.]+)"
                append_tech_with_version_debug(
                    detected_headers["cms"],
                    debug_info["cms"],
                    sources_info["cms"],
                    name,
                    header_value,
                    regex,
                    source=f"header:{key}",
                    matched=f"header:{key}={header_value}",
                )
                break

    # Detect frameworks from headers
    for name, signatures in framework_signatures.items():
        for key, value_pattern in signatures.get("headers", []):
            header_value = normalized_headers.get(key)
            if header_value and (
                not value_pattern
                or re.search(value_pattern, header_value, re.IGNORECASE)
            ):
                regex = rf"{re.escape(name.lower())}[\s\/-]+([\d\.]+)"
                append_tech_with_version_debug(
                    detected_headers["frameworks"],
                    debug_info["frameworks"],
                    sources_info["frameworks"],
                    name,
                    header_value,
                    regex,
                    source=f"header:{key}",
                    matched=f"header:{key}={header_value}",
                )
                break

    # Detect web servers from headers
    server_value = normalized_headers.get("server", "")
    for server_name, sig in server_signatures.items():
        patterns = sig.get("patterns", [])
        found = False

        for pattern in patterns:
            match = re.search(
                pattern + r"[\/-]?([\d\.]+)?", server_value, re.IGNORECASE
            )
            if match:
                version = (
                    match.group(1) if match.lastindex and match.lastindex >= 1 else None
                )
                label = f"{server_name} {version}" if version else server_name

                if label not in detected_headers["servers"]:
                    detected_headers["servers"].append(label)
                    if debug_enabled:
                        debug_info["servers"][server_name] = {
                            "matched": f"header:server={server_value}",
                            "source": "headers",
                        }
                    if server_name not in sources_info["servers"]:
                        sources_info["servers"][server_name] = set()
                    sources_info["servers"][server_name].add("headers")
                found = True
                break

        if found:
            continue

        # Check other headers for server info
        for key, _ in sig.get("headers", []):
            if key == "server":
                continue
            value = normalized_headers.get(key)
            if not value:
                continue

            for pattern in patterns:
                match = re.search(pattern + r"[\/-]?([\d\.]+)?", value, re.IGNORECASE)
                if match:
                    version = (
                        match.group(1)
                        if match.lastindex and match.lastindex >= 1
                        else None
                    )
                    label = f"{server_name} {version}" if version else server_name

                    if label not in detected_headers["servers"]:
                        detected_headers["servers"].append(label)
                        if debug_enabled:
                            debug_info["servers"][server_name] = {
                                "matched": f"header:{key}={value}",
                                "source": "headers",
                            }
                        if server_name not in sources_info["servers"]:
                            sources_info["servers"][server_name] = set()
                        sources_info["servers"][server_name].add("headers")
                    break

    # Detect other technologies (PHP, ASP.NET, etc.)
    x_powered = normalized_headers.get("x-powered-by", "")
    other_signatures = {
        "PHP": r"php[\s\/-]?([\d\.]+)",
        "ASP.NET": r"asp\.net[\s\/-]?([\d\.]+)",
    }

    for name, pattern in other_signatures.items():
        if re.search(pattern, x_powered, re.IGNORECASE):
            append_tech_with_version_debug(
                detected_headers["other"],
                debug_info["other"],
                sources_info["other"],
                name,
                x_powered,
                pattern,
                source="header:x-powered-by",
                matched=f"x-powered-by={x_powered}",
            )

    # Sort results
    for category in detected_headers:
        detected_headers[category].sort()

    return {
        "detected_headers": detected_headers,
        "debug_info": debug_info,
        "sources_info": sources_info,
    }
