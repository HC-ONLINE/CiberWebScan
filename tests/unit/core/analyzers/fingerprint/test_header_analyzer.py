"""Unit tests for fingerprint header analyzer."""

from __future__ import annotations

from ciberwebscan.core.analyzers.fingerprint.header_analyzer import analyze_headers


class TestAnalyzeHeaders:
    """Tests for analyze_headers function."""

    def test_empty_headers(self) -> None:
        """Test analyzing empty headers."""
        result = analyze_headers({}, {}, {}, {})

        assert "detected_headers" in result
        assert "sources_info" in result
        assert len(result["detected_headers"]["cms"]) == 0
        assert len(result["detected_headers"]["frameworks"]) == 0
        assert len(result["detected_headers"]["servers"]) == 0

    def test_detect_server_nginx(self) -> None:
        """Test detecting nginx server."""
        headers = {"Server": "nginx/1.18.0"}
        server_signatures = {
            "nginx": {
                "patterns": ["nginx"],
            }
        }

        result = analyze_headers(headers, {}, {}, server_signatures)
        servers = result["detected_headers"]["servers"]

        assert len(servers) == 1
        assert "nginx 1.18.0" in servers

    def test_detect_server_apache(self) -> None:
        """Test detecting Apache server."""
        headers = {"Server": "Apache/2.4.41"}
        server_signatures = {
            "Apache": {
                "patterns": ["Apache"],
            }
        }

        result = analyze_headers(headers, {}, {}, server_signatures)
        servers = result["detected_headers"]["servers"]

        assert len(servers) == 1
        assert "Apache 2.4.41" in servers

    def test_detect_cms_from_header(self) -> None:
        """Test detecting CMS from header."""
        headers = {"X-Powered-By": "WordPress"}
        cms_signatures = {
            "WordPress": {
                "headers": [("x-powered-by", "WordPress")],
            }
        }

        result = analyze_headers(headers, cms_signatures, {}, {})
        cms = result["detected_headers"]["cms"]

        assert len(cms) == 1
        assert any("WordPress" in c for c in cms)

    def test_detect_framework_express(self) -> None:
        """Test detecting Express.js framework."""
        headers = {"X-Powered-By": "Express"}
        framework_signatures = {
            "Express": {
                "headers": [("x-powered-by", "Express")],
            }
        }

        result = analyze_headers(headers, {}, framework_signatures, {})
        frameworks = result["detected_headers"]["frameworks"]

        assert len(frameworks) == 1
        assert any("Express" in f for f in frameworks)

    def test_detect_php_from_x_powered_by(self) -> None:
        """Test detecting PHP from X-Powered-By."""
        headers = {"X-Powered-By": "PHP/7.4.3"}

        result = analyze_headers(headers, {}, {}, {})
        other = result["detected_headers"]["other"]

        assert len(other) == 1
        assert "PHP 7.4.3" in other

    def test_detect_aspnet_from_x_powered_by(self) -> None:
        """Test detecting ASP.NET from X-Powered-By."""
        headers = {"X-Powered-By": "ASP.NET 4.0"}

        result = analyze_headers(headers, {}, {}, {})
        other = result["detected_headers"]["other"]

        assert len(other) == 1
        assert "ASP.NET 4.0" in other

    def test_header_case_insensitive(self) -> None:
        """Test that header names are case insensitive."""
        headers = {"SERVER": "nginx/1.18.0", "X-POWERED-BY": "PHP/7.4"}
        server_signatures = {
            "nginx": {"patterns": ["nginx"]},
        }

        result = analyze_headers(headers, {}, {}, server_signatures)

        assert "nginx 1.18.0" in result["detected_headers"]["servers"]
        assert "PHP 7.4" in result["detected_headers"]["other"]

    def test_sources_info_populated(self) -> None:
        """Test that sources info is populated."""
        headers = {"Server": "nginx/1.18.0"}
        server_signatures = {
            "nginx": {"patterns": ["nginx"]},
        }

        result = analyze_headers(headers, {}, {}, server_signatures, debug_enabled=True)

        assert "nginx" in result["sources_info"]["servers"]
        assert "headers" in result["sources_info"]["servers"]["nginx"]

    def test_multiple_technologies(self) -> None:
        """Test detecting multiple technologies."""
        headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3",
            "X-Generator": "WordPress 5.8",
        }
        server_signatures = {
            "nginx": {"patterns": ["nginx"]},
        }
        cms_signatures = {
            "WordPress": {"headers": [("x-generator", "WordPress")]},
        }

        result = analyze_headers(headers, cms_signatures, {}, server_signatures)

        assert "nginx 1.18.0" in result["detected_headers"]["servers"]
        assert "PHP 7.4.3" in result["detected_headers"]["other"]
        assert any("WordPress" in c for c in result["detected_headers"]["cms"])

    def test_results_sorted(self) -> None:
        """Test that results are sorted."""
        headers = {
            "X-Powered-By": "PHP/7.4",
            "Server": "Apache/2.4",
        }
        server_signatures = {
            "Apache": {"patterns": ["Apache"]},
        }

        result = analyze_headers(headers, {}, {}, server_signatures)

        # Results should be sorted alphabetically
        for category in result["detected_headers"].values():
            assert category == sorted(category)
