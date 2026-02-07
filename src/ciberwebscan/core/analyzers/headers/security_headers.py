"""Security headers analyzer for CiberWebScan.

Analyzes HTTP security headers including CSP, HSTS, frame protection,
and other important security directives.
"""

from __future__ import annotations

import re
from typing import Any


class SecurityHeadersAnalyzer:
    """Analyzer for HTTP security headers."""

    def __init__(self):
        """Initialize security headers analyzer."""
        pass

    def analyze(self, headers: dict[str, str]) -> dict[str, Any]:
        """Analyze security headers from HTTP response.

        Args:
            headers: Dictionary of HTTP headers (case-insensitive).

        Returns:
            Dictionary containing analysis results for each security header.
        """
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        return {
            "csp": self._analyze_csp(
                normalized_headers.get("content-security-policy", "")
            ),
            "hsts": self._analyze_hsts(
                normalized_headers.get("strict-transport-security", "")
            ),
            "frame_options": self._analyze_frame_options(
                normalized_headers.get("x-frame-options", "")
            ),
            "content_type_nosniff": self._analyze_content_type_nosniff(
                normalized_headers.get("x-content-type-options", "")
            ),
            "xss_protection": self._analyze_xss_protection(
                normalized_headers.get("x-xss-protection", "")
            ),
            "referrer_policy": self._analyze_referrer_policy(
                normalized_headers.get("referrer-policy", "")
            ),
            "permissions_policy": self._analyze_permissions_policy(
                normalized_headers.get("permissions-policy", "")
            ),
        }

    def _analyze_csp(self, csp_header: str) -> dict[str, Any]:
        """Analyze Content-Security-Policy header."""
        result = {
            "enabled": bool(csp_header),
            "default_src": False,
            "script_src": False,
            "unsafe_inline": False,
            "unsafe_eval": False,
            "wildcard": False,
            "score": 0,
        }

        if not csp_header:
            return result

        # Analyze default-src
        default_flags = self._extract_csp_flags(csp_header, "default-src")
        result["default_src"] = default_flags["exists"]

        # Analyze script-src
        script_flags = self._extract_csp_flags(csp_header, "script-src")
        result["script_src"] = script_flags["exists"]

        # Mark unsafe directives
        result["unsafe_inline"] = (
            default_flags["unsafe_inline"] or script_flags["unsafe_inline"]
        )
        result["unsafe_eval"] = (
            default_flags["unsafe_eval"] or script_flags["unsafe_eval"]
        )
        result["wildcard"] = default_flags["wildcard"] or script_flags["wildcard"]

        # Calculate score
        score = 0
        if result["enabled"]:
            score += 30
        if result["default_src"] or result["script_src"]:
            score += 40
        if not result["unsafe_inline"]:
            score += 15
        if not result["unsafe_eval"]:
            score += 10
        if not result["wildcard"]:
            score += 5

        result["score"] = min(100, score)
        return result

    def _extract_csp_flags(self, csp_header: str, directive: str) -> dict[str, bool]:
        """Extract flags from CSP directive."""
        flags = {
            "exists": False,
            "unsafe_inline": False,
            "unsafe_eval": False,
            "wildcard": False,
        }

        if not csp_header:
            return flags

        # Find directive
        directive_pattern = re.compile(rf"{directive}([^;]+)(?:;|$)", re.IGNORECASE)
        match = directive_pattern.search(csp_header)

        if match:
            flags["exists"] = True
            value = match.group(1).lower()
            if "'unsafe-inline'" in value:
                flags["unsafe_inline"] = True
            if "'unsafe-eval'" in value:
                flags["unsafe_eval"] = True
            if "*" in value:
                flags["wildcard"] = True

        return flags

    def _analyze_hsts(self, hsts_header: str) -> dict[str, Any]:
        """Analyze Strict-Transport-Security header."""
        result = {
            "enabled": bool(hsts_header),
            "max_age": None,
            "strong": False,
            "score": 0,
        }

        if not hsts_header:
            return result

        # Find max-age
        max_age_match = re.search(r"max-age=([0-9]+)", hsts_header, re.IGNORECASE)
        if max_age_match:
            try:
                max_age = int(max_age_match.group(1))
                result["max_age"] = max_age
                if max_age >= 31536000:  # 1 year
                    result["strong"] = True
            except ValueError:
                pass

        # Calculate score
        score = 0
        if result["enabled"]:
            score += 50
        if result["strong"]:
            score += 50

        result["score"] = score
        return result

    def _analyze_frame_options(self, frame_options: str) -> dict[str, Any]:
        """Analyze X-Frame-Options header."""
        result = {
            "enabled": bool(frame_options),
            "value": frame_options.upper() if frame_options else None,
            "secure": False,
            "score": 0,
        }

        if frame_options:
            value = frame_options.upper()
            if value in ["DENY", "SAMEORIGIN"]:
                result["secure"] = True
                result["score"] = 100
            elif value.startswith("ALLOW-FROM"):
                result["score"] = 70
            else:
                result["score"] = 30

        return result

    def _analyze_content_type_nosniff(self, nosniff_header: str) -> dict[str, Any]:
        """Analyze X-Content-Type-Options header."""
        result = {"enabled": bool(nosniff_header), "nosniff": False, "score": 0}

        if nosniff_header and nosniff_header.lower() == "nosniff":
            result["nosniff"] = True
            result["score"] = 100
        elif nosniff_header:
            result["score"] = 50

        return result

    def _analyze_xss_protection(self, xss_header: str) -> dict[str, Any]:
        """Analyze X-XSS-Protection header (deprecated but still relevant)."""
        result = {"enabled": bool(xss_header), "mode": None, "score": 0}

        if xss_header:
            if "1; mode=block" in xss_header.lower():
                result["mode"] = "block"
                result["score"] = 80
            elif xss_header.startswith("1"):
                result["mode"] = "filter"
                result["score"] = 60
            elif xss_header == "0":
                result["mode"] = "disabled"
                result["score"] = 0
            else:
                result["score"] = 30

        return result

    def _analyze_referrer_policy(self, referrer_header: str) -> dict[str, Any]:
        """Analyze Referrer-Policy header."""
        secure_policies = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ]

        result = {
            "enabled": bool(referrer_header),
            "policy": referrer_header.lower() if referrer_header else None,
            "secure": False,
            "score": 0,
        }

        if referrer_header:
            policy = referrer_header.lower()
            if policy in secure_policies:
                result["secure"] = True
                result["score"] = 100
            else:
                result["score"] = 50

        return result

    def _analyze_permissions_policy(self, permissions_header: str) -> dict[str, Any]:
        """Analyze Permissions-Policy header (formerly Feature-Policy)."""
        result = {"enabled": bool(permissions_header), "directives": [], "score": 0}

        if permissions_header:
            # Simple parsing of directive count
            directives = [d.strip() for d in permissions_header.split(",")]
            result["directives"] = directives
            result["score"] = min(100, len(directives) * 10)

        return result
