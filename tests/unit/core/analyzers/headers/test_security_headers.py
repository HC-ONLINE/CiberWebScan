"""Unit tests for SecurityHeadersAnalyzer with required_headers config."""

from __future__ import annotations

from ciberwebscan.core.analyzers.headers.security_headers import (
    _DEFAULT_REQUIRED_HEADERS,
    SecurityHeadersAnalyzer,
)


class TestSecurityHeadersAnalyzerInit:
    """Tests for SecurityHeadersAnalyzer initialization."""

    def test_default_required_headers(self) -> None:
        """Test default required headers list is used when none provided."""
        analyzer = SecurityHeadersAnalyzer()
        assert analyzer.required_headers == _DEFAULT_REQUIRED_HEADERS

    def test_custom_required_headers(self) -> None:
        """Test custom required headers list."""
        custom = ["X-Custom-Header", "X-Another"]
        analyzer = SecurityHeadersAnalyzer(required_headers=custom)
        assert analyzer.required_headers == custom


class TestMissingRequiredHeaders:
    """Tests for missing required headers detection."""

    def test_all_required_present(self) -> None:
        """No missing headers when all required are present."""
        analyzer = SecurityHeadersAnalyzer(
            required_headers=["Strict-Transport-Security", "X-Frame-Options"]
        )
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
        }
        result = analyzer.analyze(headers)
        assert result["missing_required"] == []

    def test_some_missing(self) -> None:
        """Detect missing required headers."""
        analyzer = SecurityHeadersAnalyzer(
            required_headers=[
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
            ]
        )
        headers = {"X-Frame-Options": "DENY"}
        result = analyzer.analyze(headers)
        missing = result["missing_required"]
        assert "Strict-Transport-Security" in missing
        assert "Content-Security-Policy" in missing
        assert "X-Frame-Options" not in missing

    def test_case_insensitive_matching(self) -> None:
        """Required headers are matched case-insensitively."""
        analyzer = SecurityHeadersAnalyzer(
            required_headers=["Strict-Transport-Security"]
        )
        headers = {"strict-transport-security": "max-age=31536000"}
        result = analyzer.analyze(headers)
        assert result["missing_required"] == []

    def test_all_missing(self) -> None:
        """All required headers missing when response has none."""
        analyzer = SecurityHeadersAnalyzer(
            required_headers=["Strict-Transport-Security", "X-Frame-Options"]
        )
        result = analyzer.analyze({})
        assert len(result["missing_required"]) == 2

    def test_no_required_headers_configured(self) -> None:
        """Empty required list means nothing is flagged as missing."""
        analyzer = SecurityHeadersAnalyzer(required_headers=[])
        result = analyzer.analyze({})
        assert result["missing_required"] == []


class TestAnalyzeReturnKeys:
    """Verify analyze always returns the expected keys."""

    def test_keys_present(self) -> None:
        """Verify that 'missing_required' key exists in output."""
        analyzer = SecurityHeadersAnalyzer()
        result = analyzer.analyze({})
        expected_keys = {
            "csp",
            "hsts",
            "frame_options",
            "content_type_nosniff",
            "xss_protection",
            "referrer_policy",
            "permissions_policy",
            "missing_required",
        }
        assert expected_keys.issubset(result.keys())
