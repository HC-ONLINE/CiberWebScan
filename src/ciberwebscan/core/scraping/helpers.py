"""
Scraping helper utilities.

Provides URL validation, robots.txt checking, content extraction,
and pagination helpers.
"""

from __future__ import annotations

import http.cookies
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup
from bs4.element import Tag

logger = logging.getLogger(__name__)

# URL validation regex
URL_REGEX = re.compile(
    r"^(?:http|https)://"  # http:// or https://
    r"(?:[\w.-]+(?::[^@]*)?@)?"  # optional user:pass@
    r"(?:[\w-]+\.)*[\w-]+"  # domain
    r"(?::\d+)?"  # optional port
    r"(?:/[^\s]*)?$",  # optional path
    re.IGNORECASE,
)

# Private IP patterns
PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\.\d+\.\d+\.\d+$"),
    re.compile(r"^192\.168\.\d+\.\d+$"),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$"),
]


def validate_url(url: str, *, allow_local: bool = False) -> bool:
    """
    Validate URL format and safety.

    Rejects dangerous schemes (file, javascript, data) and optionally
    rejects localhost/private IPs.

    Args:
        url: URL to validate.
        allow_local: Whether to allow localhost and private IPs.

    Returns:
        True if URL is valid and safe.

    Examples:
        >>> validate_url('https://example.com')
        True
        >>> validate_url('file:///etc/passwd')
        False
        >>> validate_url('http://localhost:8080', allow_local=True)
        True
    """
    if not URL_REGEX.match(url):
        return False

    parsed = urlparse(url)

    # Reject dangerous schemes
    if parsed.scheme not in {"http", "https"}:
        return False

    host = parsed.hostname or ""

    # Check localhost
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return allow_local

    # Check private IPs
    if not allow_local:
        for pattern in PRIVATE_IP_PATTERNS:
            if pattern.match(host):
                return False

    return True


def check_robots_txt(
    url: str,
    user_agent: str,
    *,
    http_client: Any = None,
) -> tuple[bool, str | None]:
    """
    Check if URL is allowed by robots.txt.

    Args:
        url: URL to check.
        user_agent: User-Agent string for the check.
        http_client: Optional HTTPClient instance. If None, uses httpx directly.

    Returns:
        Tuple of (is_allowed, reason).
        - (True, None) if allowed or on error
        - (False, "message") if explicitly denied

    Examples:
        >>> allowed, reason = check_robots_txt('https://example.com/page', 'MyBot/1.0')
        >>> if not allowed:
        ...     print(f"Blocked: {reason}")
    """
    # Validate URL first
    if not validate_url(url, allow_local=True):
        return False, "Invalid URL format"

    try:
        parsed = urlparse(url)
        robots_url = urlunparse(
            (parsed.scheme, parsed.netloc, "/robots.txt", "", "", "")
        )

        # Fetch robots.txt
        if http_client:
            response = http_client.get(
                robots_url,
                headers={"User-Agent": user_agent},
            )
            robots_content = response.text
        else:
            import httpx

            response = httpx.get(
                robots_url,
                headers={"User-Agent": user_agent},
                timeout=10.0,
                follow_redirects=True,
            )
            robots_content = response.text

        # Parse robots.txt
        rp = RobotFileParser()
        rp.parse(robots_content.splitlines())

        if not rp.can_fetch(user_agent, url):
            reason = f"Access denied by robots.txt for User-Agent '{user_agent}'"
            logger.warning(f"robots.txt: {reason} - URL: {url}")
            return False, reason

        return True, None

    except Exception as e:
        # On error, allow access (fail open)
        logger.debug(f"Error checking robots.txt for {url}: {e}")
        return True, None


def find_next_page_url(
    soup: BeautifulSoup,
    pagination_selector: str,
    current_url: str,
) -> str | None:
    """
    Find the next page URL from pagination link.

    Args:
        soup: BeautifulSoup object of current page.
        pagination_selector: CSS selector for pagination link.
        current_url: Current URL for resolving relative links.

    Returns:
        Absolute URL of next page, or None if not found.

    Examples:
        >>> soup = BeautifulSoup('<a class="next" href="/page/2">Next</a>', 'html.parser')
        >>> find_next_page_url(soup, 'a.next', 'https://example.com/page/1')
        'https://example.com/page/2'
    """
    next_link = soup.select_one(pagination_selector)

    if next_link and next_link.has_attr("href"):
        next_url = str(next_link["href"]).strip()

        # Skip empty or javascript: hrefs
        if not next_url or next_url.startswith(("javascript:", "#")):
            return None

        # Convert relative to absolute URL
        if not next_url.startswith(("http://", "https://")):
            next_url = urljoin(current_url, next_url)

        return next_url

    return None


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
    """
    Parse cookie string to dictionary.

    Args:
        cookie_str: Cookie string in format 'name1=value1; name2=value2'.

    Returns:
        Dictionary of cookie name-value pairs.

    Examples:
        >>> parse_cookie_string('session=abc123; token=xyz')
        {'session': 'abc123', 'token': 'xyz'}
    """
    if not cookie_str:
        return {}

    cookies = {}

    try:
        for cookie in cookie_str.split(";"):
            cookie = cookie.strip()
            if not cookie or "=" not in cookie:
                continue

            name, value = cookie.split("=", 1)
            cookies[name.strip()] = value.strip()

    except Exception as e:
        logger.error(f"Error parsing cookies: {e}")

    return cookies


def parse_set_cookie_headers(headers: dict[str, Any]) -> dict[str, str]:
    """
    Parse Set-Cookie headers into cookie name-value pairs.

    Args:
        headers: HTTP response headers dictionary.

    Returns:
        Dictionary of cookie name-value pairs.

    Examples:
        >>> headers = {'Set-Cookie': 'session=abc; Secure; HttpOnly'}
        >>> cookies = parse_set_cookie_headers(headers)
        >>> cookies['session']
        'abc'
    """
    cookies: dict[str, str] = {}

    # Collect all set-cookie values
    set_cookie_values = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            if isinstance(value, list):
                set_cookie_values.extend(value)
            else:
                set_cookie_values.append(value)

    if not set_cookie_values:
        return cookies

    for cookie_header in set_cookie_values:
        simple_cookie = http.cookies.SimpleCookie()

        try:
            simple_cookie.load(cookie_header)
        except Exception:
            # Try parsing manually if SimpleCookie fails
            for part in cookie_header.split(","):
                try:
                    simple_cookie.load(part)
                except Exception:
                    continue

        for morsel in simple_cookie.values():
            cookies[morsel.key] = morsel.value

    return cookies


def extract_text(element: Tag | None) -> str:
    """
    Extract clean text from BeautifulSoup element.

    Args:
        element: BeautifulSoup Tag element or None.

    Returns:
        Stripped text content, or empty string if element is None.
    """
    if element is None:
        return ""
    return element.get_text(strip=True)


def extract_attribute(element: Tag | None, attr: str, default: Any = None) -> Any:
    """
    Extract attribute value from BeautifulSoup element.

    Args:
        element: BeautifulSoup Tag element or None.
        attr: Attribute name to extract.
        default: Default value if attribute not found or element is None.

    Returns:
        Attribute value or default.
    """
    if element is None:
        return default
    return element.get(attr, default)


def process_elements(
    elements: list[Tag],
    attributes: list[str] | None = None,
    schema: dict[str, Any] | None = None,
    extractor: Any | None = None,
) -> list[dict[str, Any]]:
    """
    Process scraped elements and extract data.

    Args:
        elements: List of BeautifulSoup elements.
        attributes: List of HTML attributes to extract.
        schema: Schema for structured extraction.
        extractor: DataExtractor instance with extract() method.

    Returns:
        List of extracted data dictionaries.

    Examples:
        >>> from bs4 import BeautifulSoup
        >>> html = '<div class="item"><a href="/link">Text</a></div>'
        >>> soup = BeautifulSoup(html, 'html.parser')
        >>> elements = soup.select('div.item')
        >>> process_elements(elements, attributes=['href'])
        [{'text': 'Text'}]
    """
    extracted_data = []

    # Use extractor with schema
    if schema and extractor:
        return [extractor.extract(el, schema) for el in elements]

    # Standard extraction
    for element in elements:
        item_data = {}

        # Always try to get text
        text = extract_text(element)
        if text:
            item_data["text"] = text

        # Extract specified attributes
        if attributes:
            for attr in attributes:
                # Try direct attribute
                attr_value = element.get(attr)
                if attr_value:
                    item_data[attr] = attr_value
                    continue

                # Try finding child with class matching attr
                child = element.select_one(f".{attr}")
                if child:
                    item_data[attr] = extract_text(child)
                    continue

                # Try finding element with tag matching attr
                tag_el = element.select_one(attr)
                if tag_el:
                    item_data[attr] = extract_text(tag_el)

        if item_data:
            extracted_data.append(item_data)

    return extracted_data
