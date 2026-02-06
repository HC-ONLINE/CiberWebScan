"""
Unit tests for scraping helpers module.

Tests URL validation, robots.txt checking, pagination,
cookie parsing, and element processing functions.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from bs4 import BeautifulSoup

from ciberwebscan.core.scraping.helpers import (
    check_robots_txt,
    extract_attribute,
    extract_text,
    find_next_page_url,
    is_safe_url,
    parse_cookie_string,
    parse_set_cookie_headers,
    process_elements,
)


class TestIsSafeUrl:
    """Tests for is_safe_url function."""

    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        assert is_safe_url("http://example.com") is True

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        assert is_safe_url("https://example.com/path?query=1") is True

    def test_empty_url(self):
        """Test empty URL returns False."""
        assert is_safe_url("") is False

    def test_none_url(self):
        """Test None-like empty URL returns False."""
        assert is_safe_url("   ") is False

    def test_invalid_scheme(self):
        """Test URL with invalid scheme."""
        assert is_safe_url("ftp://example.com") is False
        assert is_safe_url("file:///etc/passwd") is False

    def test_missing_scheme(self):
        """Test URL without scheme."""
        assert is_safe_url("example.com") is False
        assert is_safe_url("www.example.com") is False

    def test_localhost_blocked_by_default(self):
        """Test localhost is blocked by default."""
        assert is_safe_url("http://localhost/") is False
        assert is_safe_url("http://127.0.0.1/") is False

    def test_localhost_allowed_when_enabled(self):
        """Test localhost allowed when allow_local=True."""
        assert is_safe_url("http://localhost/", allow_local=True) is True
        assert is_safe_url("http://127.0.0.1/", allow_local=True) is True

    def test_private_ip_blocked_by_default(self):
        """Test private IPs are blocked by default."""
        assert is_safe_url("http://192.168.1.1/") is False
        assert is_safe_url("http://10.0.0.1/") is False
        assert is_safe_url("http://172.16.0.1/") is False

    def test_private_ip_allowed_when_enabled(self):
        """Test private IPs allowed when allow_local=True."""
        assert is_safe_url("http://192.168.1.1/", allow_local=True) is True
        assert is_safe_url("http://10.0.0.1/", allow_local=True) is True

    def test_url_with_port(self):
        """Test URL with port number."""
        assert is_safe_url("https://example.com:8080/api") is True

    def test_url_with_auth(self):
        """Test URL with authentication."""
        assert is_safe_url("https://user:pass@example.com/") is True

    def test_ipv6_url(self):
        """Test IPv6 URL handling."""
        # IPv6 loopback should be blocked
        assert is_safe_url("http://[::1]/") is False

    def test_malformed_url(self):
        """Test malformed URL returns False."""
        assert is_safe_url("not-a-url") is False
        assert is_safe_url("://missing-scheme") is False


class TestCheckRobotsTxt:
    """Tests for check_robots_txt function."""

    def test_robots_allows_crawling(self):
        """Test when robots.txt allows crawling."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "User-agent: *\nAllow: /"
        mock_client.get.return_value = mock_response

        allowed, reason = check_robots_txt(
            "https://example.com/page",
            "TestBot/1.0",
            http_client=mock_client,
        )

        assert allowed is True
        assert reason is None

    def test_robots_disallows_crawling(self):
        """Test when robots.txt disallows crawling."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "User-agent: *\nDisallow: /"
        mock_client.get.return_value = mock_response

        allowed, reason = check_robots_txt(
            "https://example.com/page",
            "TestBot/1.0",
            http_client=mock_client,
        )

        assert allowed is False
        assert reason is not None
        assert "robots.txt" in reason.lower()

    def test_robots_not_found(self):
        """Test when robots.txt returns 404."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client.get.return_value = mock_response

        allowed, reason = check_robots_txt(
            "https://example.com/page",
            "TestBot/1.0",
            http_client=mock_client,
        )

        # No robots.txt means allowed
        assert allowed is True

    def test_robots_request_error(self):
        """Test handling of request errors."""
        mock_client = MagicMock()
        mock_client.get.side_effect = Exception("Network error")

        allowed, reason = check_robots_txt(
            "https://example.com/page",
            "TestBot/1.0",
            http_client=mock_client,
        )

        # Error fetching should default to allowed
        assert allowed is True

    def test_robots_specific_user_agent(self):
        """Test robots.txt with specific user agent rules."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
User-agent: BadBot
Disallow: /

User-agent: *
Allow: /
"""
        mock_client.get.return_value = mock_response

        # GoodBot should be allowed
        allowed, _ = check_robots_txt(
            "https://example.com/page",
            "GoodBot/1.0",
            http_client=mock_client,
        )
        assert allowed is True

    def test_invalid_url_returns_false(self):
        """Test that invalid URL returns False."""
        allowed, reason = check_robots_txt(
            "not-a-valid-url",
            "TestBot/1.0",
        )
        assert allowed is False
        assert reason is not None


class TestFindNextPageUrl:
    """Tests for find_next_page_url function."""

    def test_find_next_link(self):
        """Test finding next page link."""
        html = """
        <html>
            <a href="/page/2" class="next">Next</a>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")

        url = find_next_page_url(soup, "a.next", "https://example.com/page/1")

        assert url == "https://example.com/page/2"

    def test_absolute_url_preserved(self):
        """Test absolute URLs are preserved."""
        html = """
        <html>
            <a href="https://other.com/page/2" class="next">Next</a>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")

        url = find_next_page_url(soup, "a.next", "https://example.com/page/1")

        assert url == "https://other.com/page/2"

    def test_no_next_link(self):
        """Test when no next link exists."""
        html = "<html><body>No pagination</body></html>"
        soup = BeautifulSoup(html, "html.parser")

        url = find_next_page_url(soup, "a.next", "https://example.com/page/1")

        assert url is None

    def test_empty_href(self):
        """Test link with empty href."""
        html = '<html><a href="" class="next">Next</a></html>'
        soup = BeautifulSoup(html, "html.parser")

        url = find_next_page_url(soup, "a.next", "https://example.com/page/1")

        assert url is None

    def test_javascript_href_ignored(self):
        """Test JavaScript href is ignored."""
        html = '<html><a href="javascript:void(0)" class="next">Next</a></html>'
        soup = BeautifulSoup(html, "html.parser")

        url = find_next_page_url(soup, "a.next", "https://example.com/")

        assert url is None

    def test_relative_path(self):
        """Test relative path resolution."""
        html = '<html><a href="page2" class="next">Next</a></html>'
        soup = BeautifulSoup(html, "html.parser")

        url = find_next_page_url(soup, "a.next", "https://example.com/list/")

        assert url == "https://example.com/list/page2"


class TestParseCookieString:
    """Tests for parse_cookie_string function."""

    def test_single_cookie(self):
        """Test parsing single cookie."""
        result = parse_cookie_string("session=abc123")
        assert result == {"session": "abc123"}

    def test_multiple_cookies(self):
        """Test parsing multiple cookies."""
        result = parse_cookie_string("session=abc; user=john; theme=dark")
        assert result == {"session": "abc", "user": "john", "theme": "dark"}

    def test_empty_string(self):
        """Test empty string returns empty dict."""
        result = parse_cookie_string("")
        assert result == {}

    def test_whitespace_handling(self):
        """Test whitespace is trimmed."""
        result = parse_cookie_string("  key = value  ;  other = data  ")
        assert result == {"key": "value", "other": "data"}

    def test_value_with_equals(self):
        """Test cookie value containing equals sign."""
        result = parse_cookie_string("token=abc=def=ghi")
        assert result == {"token": "abc=def=ghi"}

    def test_empty_value(self):
        """Test cookie with empty value."""
        result = parse_cookie_string("empty=; other=value")
        assert result == {"empty": "", "other": "value"}


class TestParseSetCookieHeaders:
    """Tests for parse_set_cookie_headers function."""

    def test_single_header(self):
        """Test parsing single Set-Cookie header."""
        headers = {"Set-Cookie": "session=abc123; Path=/; HttpOnly"}
        result = parse_set_cookie_headers(headers)
        assert result == {"session": "abc123"}

    def test_multiple_cookies_in_list(self):
        """Test parsing multiple Set-Cookie headers as list."""
        headers = {
            "Set-Cookie": [
                "session=abc; Path=/",
                "user=john; Path=/; Secure",
            ]
        }
        result = parse_set_cookie_headers(headers)
        assert result == {"session": "abc", "user": "john"}

    def test_empty_headers(self):
        """Test empty headers."""
        result = parse_set_cookie_headers({})
        assert result == {}

    def test_no_set_cookie_header(self):
        """Test when no Set-Cookie header exists."""
        headers = {"Content-Type": "text/html"}
        result = parse_set_cookie_headers(headers)
        assert result == {}


class TestExtractText:
    """Tests for extract_text function."""

    def test_simple_text(self):
        """Test extracting simple text."""
        html = "<p>Hello World</p>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.p

        result = extract_text(element)
        assert result == "Hello World"

    def test_nested_text(self):
        """Test extracting text from nested elements."""
        html = "<div><span>Hello</span> <b>World</b></div>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.div

        result = extract_text(element)
        assert "Hello" in result
        assert "World" in result

    def test_whitespace_stripped(self):
        """Test whitespace is stripped."""
        html = "<p>   Padded Text   </p>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.p

        result = extract_text(element)
        assert result == "Padded Text"

    def test_none_element(self):
        """Test None element returns empty string."""
        result = extract_text(None)
        assert result == ""


class TestExtractAttribute:
    """Tests for extract_attribute function."""

    def test_existing_attribute(self):
        """Test extracting existing attribute."""
        html = '<a href="https://example.com">Link</a>'
        soup = BeautifulSoup(html, "html.parser")
        element = soup.a

        result = extract_attribute(element, "href")
        assert result == "https://example.com"

    def test_missing_attribute(self):
        """Test missing attribute returns None."""
        html = "<a>Link without href</a>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.a

        result = extract_attribute(element, "href")
        assert result is None

    def test_default_value(self):
        """Test default value for missing attribute."""
        html = "<a>Link</a>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.a

        result = extract_attribute(element, "href", default="no-link")
        assert result == "no-link"

    def test_none_element(self):
        """Test None element returns default."""
        result = extract_attribute(None, "href", default="fallback")
        assert result == "fallback"

    def test_class_attribute(self):
        """Test extracting class attribute (returns list in BS4)."""
        html = '<div class="one two three">Content</div>'
        soup = BeautifulSoup(html, "html.parser")
        element = soup.div

        result = extract_attribute(element, "class")
        # BS4 returns class as list
        assert isinstance(result, list)
        assert "one" in result


class TestProcessElements:
    """Tests for process_elements function."""

    def test_basic_processing(self):
        """Test basic element processing."""
        html = """
        <div class="item"><h2>Title 1</h2><p>Description 1</p></div>
        <div class="item"><h2>Title 2</h2><p>Description 2</p></div>
        """
        soup = BeautifulSoup(html, "html.parser")
        elements = soup.select("div.item")

        result = process_elements(elements)

        assert len(result) == 2
        assert "text" in result[0]
        assert "Title 1" in result[0]["text"]

    def test_with_attributes(self):
        """Test processing with specific attributes."""
        html = """
        <a href="/link1" title="Link 1">First</a>
        <a href="/link2" title="Link 2">Second</a>
        """
        soup = BeautifulSoup(html, "html.parser")
        elements = soup.select("a")

        result = process_elements(elements, attributes=["href", "title"])

        assert len(result) == 2
        assert result[0]["href"] == "/link1"
        assert result[0]["title"] == "Link 1"

    def test_empty_elements(self):
        """Test empty element list."""
        result = process_elements([])
        assert result == []

    def test_with_schema(self):
        """Test processing with schema."""
        html = """
        <div class="product">
            <span class="name">Product A</span>
            <span class="price">$10.00</span>
        </div>
        """
        soup = BeautifulSoup(html, "html.parser")
        elements = soup.select("div.product")

        from ciberwebscan.core.scraping.extractor import DataExtractor

        extractor = DataExtractor()
        schema = {
            "name": {"selector": ".name"},
            "price": {"selector": ".price"},
        }

        result = process_elements(elements, schema=schema, extractor=extractor)

        assert len(result) == 1
        assert result[0]["name"] == "Product A"
        assert result[0]["price"] == "$10.00"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_is_safe_url_with_unicode(self):
        """Test URL with unicode characters."""
        assert is_safe_url("https://example.com/путь") is True

    def test_is_safe_url_with_encoded_chars(self):
        """Test URL with encoded characters."""
        assert is_safe_url("https://example.com/path%20with%20spaces") is True

    def test_cookie_parsing_with_special_chars(self):
        """Test cookie parsing with special characters."""
        result = parse_cookie_string("token=abc%20def; path=/test")
        assert "token" in result

    def test_find_next_page_with_button(self):
        """Test finding next page with button element."""
        html = """
        <html>
            <button data-url="/page/2" class="next">Next</button>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")

        # Button doesn't have href, so should return None
        url = find_next_page_url(soup, "button.next", "https://example.com/")

        assert url is None
