"""Unit tests for fingerprint HTML analyzer."""

from __future__ import annotations

from ciberwebscan.core.analyzers.fingerprint.html_analyzer import analyze_html_content


class TestAnalyzeHtmlContent:
    """Tests for analyze_html_content function."""

    def test_empty_html(self) -> None:
        """Test analyzing empty HTML."""
        result = analyze_html_content("", {}, {}, {})

        assert "detected_html" in result
        assert len(result["detected_html"]["cms"]) == 0

    def test_detect_wordpress_from_generator(self) -> None:
        """Test detecting WordPress from meta generator."""
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 5.8.1">
        </head>
        </html>
        """
        cms_signatures = {
            "WordPress": {"headers": []},
        }

        result = analyze_html_content(html, cms_signatures, {}, {})
        cms = result["detected_html"]["cms"]

        assert len(cms) == 1
        assert "WordPress 5.8.1" in cms

    def test_detect_drupal_from_generator(self) -> None:
        """Test detecting Drupal from meta generator."""
        html = """
        <html>
        <head>
            <meta name="generator" content="Drupal 9 (https://www.drupal.org)">
        </head>
        </html>
        """
        cms_signatures = {
            "Drupal": {"headers": []},
        }

        result = analyze_html_content(html, cms_signatures, {}, {})
        cms = result["detected_html"]["cms"]

        assert len(cms) == 1
        assert any("Drupal" in c for c in cms)

    def test_detect_cms_from_content_pattern(self) -> None:
        """Test detecting CMS from content pattern."""
        html = """
        <html>
        <body>
            <link rel="stylesheet" href="/wp-content/themes/theme/style.css">
        </body>
        </html>
        """
        cms_signatures = {
            "WordPress": {
                "content_patterns": ["wp-content"],
            }
        }

        result = analyze_html_content(html, cms_signatures, {}, {})
        cms = result["detected_html"]["cms"]

        assert len(cms) == 1
        assert "WordPress" in cms

    def test_detect_jquery_from_script(self) -> None:
        """Test detecting jQuery from script tag."""
        html = """
        <html>
        <head>
            <script src="/js/jquery-3.6.0.min.js"></script>
        </head>
        </html>
        """
        js_signatures = {
            "jQuery": {
                "script_patterns": [r"jquery"],
            }
        }

        result = analyze_html_content(html, {}, {}, js_signatures)
        js = result["detected_html"]["js_libraries"]

        assert len(js) == 1
        assert any("jQuery" in lib for lib in js)

    def test_detect_bootstrap_from_css(self) -> None:
        """Test detecting Bootstrap from CSS link."""
        html = """
        <html>
        <head>
            <link rel="stylesheet" href="/css/bootstrap-5.2.0.min.css">
        </head>
        </html>
        """
        js_signatures = {
            "Bootstrap": {
                "css_patterns": [r"bootstrap"],
            }
        }

        result = analyze_html_content(html, {}, {}, js_signatures)
        js = result["detected_html"]["js_libraries"]

        assert len(js) == 1
        assert any("Bootstrap" in lib for lib in js)

    def test_detect_php(self) -> None:
        """Test detecting PHP from content."""
        html = """
        <html>
        <body>
            <a href="page.php">Link</a>
        </body>
        </html>
        """

        result = analyze_html_content(html, {}, {}, {})
        other = result["detected_html"]["other"]

        assert "PHP" in other

    def test_detect_cloudflare_cdn(self) -> None:
        """Test detecting Cloudflare CDN."""
        html = """
        <html>
        <head>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        </head>
        </html>
        """

        result = analyze_html_content(html, {}, {}, {})
        other = result["detected_html"]["other"]

        assert "Cloudflare CDN" in other

    def test_detect_google_cdn(self) -> None:
        """Test detecting Google CDN."""
        html = """
        <html>
        <head>
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        </head>
        </html>
        """

        result = analyze_html_content(html, {}, {}, {})
        other = result["detected_html"]["other"]

        assert "Google CDN" in other

    def test_detect_framework_from_meta(self) -> None:
        """Test detecting framework from meta tag."""
        html = """
        <html>
        <head>
            <meta name="application-name" content="Laravel Application">
        </head>
        </html>
        """
        framework_signatures = {
            "Laravel": {"headers": []},
        }

        result = analyze_html_content(html, {}, framework_signatures, {})
        frameworks = result["detected_html"]["frameworks"]

        assert len(frameworks) == 1
        assert any("Laravel" in f for f in frameworks)

    def test_multiple_scripts(self) -> None:
        """Test detecting multiple JS libraries."""
        html = """
        <html>
        <head>
            <script src="/js/jquery.min.js"></script>
            <script src="/js/angular.min.js"></script>
        </head>
        </html>
        """
        js_signatures = {
            "jQuery": {"script_patterns": [r"jquery"]},
            "Angular": {"script_patterns": [r"angular"]},
        }

        result = analyze_html_content(html, {}, {}, js_signatures)
        js = result["detected_html"]["js_libraries"]

        assert len(js) == 2

    def test_sources_info_populated(self) -> None:
        """Test that sources info is populated."""
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 5.8">
        </head>
        </html>
        """
        cms_signatures = {"WordPress": {}}

        result = analyze_html_content(html, cms_signatures, {}, {}, debug_enabled=True)

        assert "WordPress" in result["sources_info"]["cms"]

    def test_results_sorted(self) -> None:
        """Test that results are sorted."""
        html = """
        <html>
        <head>
            <script src="/js/vue.js"></script>
            <script src="/js/angular.js"></script>
        </head>
        </html>
        """
        js_signatures = {
            "Vue": {"script_patterns": [r"vue"]},
            "Angular": {"script_patterns": [r"angular"]},
        }

        result = analyze_html_content(html, {}, {}, js_signatures)
        js = result["detected_html"]["js_libraries"]

        assert js == sorted(js)

    def test_no_script_src(self) -> None:
        """Test handling script tags without src."""
        html = """
        <html>
        <body>
            <script>
                console.log("inline script");
            </script>
        </body>
        </html>
        """

        result = analyze_html_content(html, {}, {}, {})
        assert len(result["detected_html"]["js_libraries"]) == 0
