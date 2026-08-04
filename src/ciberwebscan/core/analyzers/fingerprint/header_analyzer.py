"""
HTTP header analyzer for technology detection.

This module provides functionality to analyze HTTP headers and detect
technologies like CMS, frameworks, web servers, CDN/PaaS, and backend
languages based on specific patterns.
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
    cdn_paas_signatures: dict[str, Any] | None = None,
    debug_enabled: bool = False,
) -> dict[str, Any]:
    """
    Analyze HTTP headers to detect web technologies used.

    This function examines HTTP headers for patterns that indicate
    the use of CMS, frameworks, web servers, CDN/PaaS, and backend languages.

    Args:
        headers: Dictionary of HTTP headers to analyze.
        cms_signatures: CMS detection signatures.
        framework_signatures: Framework detection signatures.
        server_signatures: Web server detection signatures.
        cdn_paas_signatures: CDN/PaaS detection signatures.
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

    # Detect backend languages from X-Powered-By and other headers
    x_powered = normalized_headers.get("x-powered-by", "")

    backend_language_signatures: dict[str, list[str]] = {
        "PHP": [r"php[\s\/-]?([\d\.]+)"],
        "ASP.NET": [r"asp\.net(?:[\s\/-]?([\d\.]+))?"],
        "Python": [r"python[\s\/-]?([\d\.]+)", r"gunicorn[\s\/-]?([\d\.]+)"],
        "Ruby": [r"ruby[\s\/-]?([\d\.]+)", r"phusion[\s\/-]?([\d\.]+)"],
        "Java": [
            r"java[\s\/-]?([\d\.]+)",
            r"servlet[\s\/-]?([\d\.]+)",
            r"jsp[\s\/-]?([\d\.]+)",
        ],
        "Node.js": [r"express[\s\/-]?([\d\.]+)", r"node[\s\/-]?([\d\.]+)"],
        "Go": [r"go[\s\/-]?([\d\.]+)"],
        "Perl": [r"perl[\s\/-]?([\d\.]+)"],
    }

    # Headers that commonly indicate backend languages
    language_indicator_headers = [
        "x-powered-by",
        "x-runtime",
        "x-generator",
        "x-appengine-version",
        "x-request-id",
        "x-application-context",
    ]

    # Detect from X-Powered-By
    for lang_name, patterns in backend_language_signatures.items():
        for pattern in patterns:
            if re.search(pattern, x_powered, re.IGNORECASE):
                append_tech_with_version_debug(
                    detected_headers["other"],
                    debug_info["other"],
                    sources_info["other"],
                    lang_name,
                    x_powered,
                    pattern,
                    source="header:x-powered-by",
                    matched=f"x-powered-by={x_powered}",
                )
                break

    # Detect from Server header (e.g., "gunicorn/20.1.0", "Cowboy")
    server_lang_hints: dict[str, str] = {
        r"\bgunicorn[\s\/-]?([\d\.]+)": "Python",
        r"\buvicorn[\s\/-]?([\d\.]+)": "Python",
        r"\bwaitress[\s\/-]?([\d\.]+)": "Python",
        r"\bpuma[\s\/-]?([\d\.]+)": "Ruby",
        r"\bthin[\s\/-]?([\d\.]+)": "Ruby",
        r"\bunicorn[\s\/-]?([\d\.]+)": "Ruby",
        r"\bpassenger[\s\/-]?([\d\.]+)": "Ruby",
        r"\bCowboy(?:[\s\/-]?([\d\.]+))?": "Erlang",
        r"\bcowboy(?:[\s\/-]?([\d\.]+))?": "Erlang",
        r"\bWEBrick(?:[\s\/-]?([\d\.]+))?": "Ruby",
        r"\bJetty[\s\/-]?([\d\.]+)": "Java",
        r"\blighttpd[\s\/-]?([\d\.]+)": "C",
        r"\bOpenResty[\s\/-]?([\d\.]+)": "Nginx/Lua",
        r"\bGo[\s\/-]+http[\s\/-]+server[\s\/-]+([\d\.]+)": "Go",
    }

    for pattern, lang_name in server_lang_hints.items():
        if re.search(pattern, server_value, re.IGNORECASE) and not any(
            lang_name in item for item in detected_headers["other"]
        ):
            append_tech_with_version_debug(
                detected_headers["other"],
                debug_info["other"],
                sources_info["other"],
                lang_name,
                server_value,
                pattern,
                source="header:server",
                matched=f"server={server_value}",
            )

    # Detect from additional indicator headers
    for hdr_key in language_indicator_headers:
        hdr_value = normalized_headers.get(hdr_key, "")
        if not hdr_value:
            continue

        # Spring/Java from x-application-context
        if hdr_key == "x-application-context":
            append_tech_with_version_debug(
                detected_headers["other"],
                debug_info["other"],
                sources_info["other"],
                "Java",
                hdr_value,
                r"(.+)",
                source=f"header:{hdr_key}",
                matched=f"{hdr_key}={hdr_value}",
            )
            continue

        # General backend language hints
        additional_lang_hints: dict[str, str] = {
            r"phusion[\s\/-]?(?:passenger)?[\s\/-]?([\d\.]+)": "Ruby",
            r"ruby[\s\/-]?([\d\.]+)": "Ruby",
        }
        for pattern, lang_name in additional_lang_hints.items():
            if re.search(pattern, hdr_value, re.IGNORECASE):
                append_tech_with_version_debug(
                    detected_headers["other"],
                    debug_info["other"],
                    sources_info["other"],
                    lang_name,
                    hdr_value,
                    pattern,
                    source=f"header:{hdr_key}",
                    matched=f"{hdr_key}={hdr_value}",
                )
                break

    # Detect CDN/PaaS from headers
    if cdn_paas_signatures:
        for provider_name, sig in cdn_paas_signatures.items():
            for key, value_pattern in sig.get("headers", []):
                header_value = normalized_headers.get(key.lower())
                if header_value and (
                    not value_pattern
                    or re.search(value_pattern, header_value, re.IGNORECASE)
                ):
                    if provider_name not in detected_headers["other"]:
                        detected_headers["other"].append(provider_name)
                        if debug_enabled:
                            debug_info["other"][provider_name] = {
                                "matched": f"header:{key}={header_value}",
                                "source": "cdn_paas_headers",
                            }
                    if provider_name not in sources_info["other"]:
                        sources_info["other"][provider_name] = set()
                    sources_info["other"][provider_name].add("cdn_paas")
                    break

    # Sort results
    for category in detected_headers:
        detected_headers[category].sort()

    return {
        "detected_headers": detected_headers,
        "debug_info": debug_info,
        "sources_info": sources_info,
    }
