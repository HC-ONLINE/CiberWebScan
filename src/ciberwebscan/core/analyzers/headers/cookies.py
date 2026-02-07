"""Cookie security analyzer for CiberWebScan.

Analyzes HTTP cookies for security attributes like Secure, HttpOnly, SameSite.
"""

from __future__ import annotations

import http.cookies
from typing import Any


class CookieAnalyzer:
    """Analyzer for HTTP cookie security."""

    def __init__(self):
        """Initialize cookie analyzer."""
        pass

    def analyze(self, headers: dict[str, str]) -> dict[str, Any]:
        """Analyze cookies from Set-Cookie headers.

        Args:
            headers: Dictionary of HTTP headers.

        Returns:
            Dictionary containing cookie security analysis.
        """
        cookies = self._extract_cookies(headers)

        result = {
            "total_cookies": len(cookies),
            "secure_cookies": 0,
            "httponly_cookies": 0,
            "samesite_cookies": 0,
            "insecure_cookies": [],
            "score": 0,
        }

        if not cookies:
            return result

        for cookie in cookies:
            if cookie.get("secure"):
                result["secure_cookies"] += 1
            if cookie.get("httponly"):
                result["httponly_cookies"] += 1
            if cookie.get("samesite"):
                result["samesite_cookies"] += 1

            # Check if cookie is insecure
            if not any(
                [cookie.get("secure"), cookie.get("httponly"), cookie.get("samesite")]
            ):
                result["insecure_cookies"].append(
                    {
                        "name": cookie["name"],
                        "issues": [
                            "missing_secure",
                            "missing_httponly",
                            "missing_samesite",
                        ],
                    }
                )

        # Calculate score
        if result["total_cookies"] > 0:
            secure_ratio = result["secure_cookies"] / result["total_cookies"]
            httponly_ratio = result["httponly_cookies"] / result["total_cookies"]
            samesite_ratio = result["samesite_cookies"] / result["total_cookies"]

            result["score"] = int(
                (secure_ratio * 40 + httponly_ratio * 40 + samesite_ratio * 20) * 100
            )

        return result

    def _extract_cookies(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Extract and parse cookies from Set-Cookie headers."""
        cookies = []

        # Find all Set-Cookie headers (case-insensitive)
        set_cookie_values = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                if isinstance(v, list):
                    set_cookie_values.extend(v)
                else:
                    set_cookie_values.append(v)

        for cookie_header in set_cookie_values:
            cookie_info = self._parse_cookie(cookie_header)
            if cookie_info:
                cookies.append(cookie_info)

        return cookies

    def _parse_cookie(self, cookie_string: str) -> dict[str, Any] | None:
        """Parse a single Set-Cookie header value."""
        try:
            simple_cookie = http.cookies.SimpleCookie()
            simple_cookie.load(cookie_string)

            # Get first (and typically only) cookie
            for morsel in simple_cookie.values():
                return {
                    "name": morsel.key,
                    "value": morsel.value,
                    "secure": bool(morsel.get("secure")),
                    "httponly": bool(morsel.get("httponly")),
                    "samesite": morsel.get("samesite"),
                    "domain": morsel.get("domain"),
                    "path": morsel.get("path"),
                    "expires": morsel.get("expires"),
                    "max_age": morsel.get("max-age"),
                }
        except Exception:
            # If parsing fails, try manual parsing
            parts = cookie_string.split(";")
            if parts:
                # First part should be name=value
                name_value = parts[0].strip().split("=", 1)
                if len(name_value) == 2:
                    cookie_info = {
                        "name": name_value[0].strip(),
                        "value": name_value[1].strip(),
                        "secure": False,
                        "httponly": False,
                        "samesite": None,
                        "domain": None,
                        "path": None,
                        "expires": None,
                        "max_age": None,
                    }

                    # Parse attributes
                    for part in parts[1:]:
                        attr = part.strip().lower()
                        if attr == "secure":
                            cookie_info["secure"] = True
                        elif attr == "httponly":
                            cookie_info["httponly"] = True
                        elif attr.startswith("samesite="):
                            cookie_info["samesite"] = attr.split("=", 1)[1]

                    return cookie_info

        return None
