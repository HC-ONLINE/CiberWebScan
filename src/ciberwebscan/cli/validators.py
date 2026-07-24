"""
Validators for CLI arguments.

Simple validation without external dependencies.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


class ValidationError(Exception):
    """Validation error with details."""

    def __init__(self, message: str, param: str | None = None):
        super().__init__(message)
        self.param = param
        self.message = message


def validate_url(url: str, allow_http: bool = True) -> str:
    """
    Validate and normalize a URL for CLI input.

    Note:
        This function normalizes URLs (adds scheme) and validates format.
        For security validation (blocking dangerous schemes, private IPs),
        use :func:`ciberwebscan.core.scraping.helpers.is_safe_url`.

    Args:
        url: URL to validate.
        allow_http: Whether to allow HTTP (non-HTTPS) URLs.

    Returns:
        Normalized URL.

    Raises:
        ValidationError: If URL is invalid.
    """
    if not url:
        raise ValidationError("URL cannot be empty", "url")

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {e}", "url") from e

    if not parsed.netloc:
        raise ValidationError("URL must have a domain", "url")

    if not allow_http and parsed.scheme == "http":
        raise ValidationError("HTTPS is required", "url")

    # Basic domain validation
    domain = parsed.netloc.split(":")[0]  # Remove port
    # Require a dot-separated domain (e.g., example.com) for public hosts,
    # but allow single-label hosts for localhost and local IPs.
    is_domain_like = bool(
        re.match(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$",
            domain,
        )
    )

    if (
        not is_domain_like
        and domain not in ("localhost", "127.0.0.1")
        and not _is_valid_ip(domain)
    ):
        raise ValidationError(f"Invalid domain: {domain}", "url")

    return url


def _is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def validate_file_path(
    path: str,
    must_exist: bool = False,
    create_parent: bool = False,
) -> Path:
    """
    Validate a file path.

    Args:
        path: Path to validate.
        must_exist: Whether the file must already exist.
        create_parent: Whether to create parent directories.

    Returns:
        Validated Path object.

    Raises:
        ValidationError: If path is invalid.
    """
    if not path:
        raise ValidationError("Path cannot be empty", "path")

    try:
        p = Path(path)
    except Exception as e:
        raise ValidationError(f"Invalid path: {e}", "path") from e

    if must_exist and not p.exists():
        raise ValidationError(f"File not found: {path}", "path")

    if create_parent and not p.parent.exists():
        p.parent.mkdir(parents=True)

    return p


def validate_format(
    format_str: str,
    allowed: list[str] | None = None,
) -> str:
    """
    Validate export format.

    Args:
        format_str: Format string to validate.
        allowed: List of allowed formats.

    Returns:
        Validated format string (lowercase).

    Raises:
        ValidationError: If format is not allowed.
    """
    allowed = allowed or ["json", "jsonl", "csv", "html"]
    fmt = format_str.lower()

    if fmt not in allowed:
        raise ValidationError(
            f"Invalid format '{format_str}'. Allowed: {', '.join(allowed)}",
            "format",
        )

    return fmt


def validate_selector(selector: str) -> str:
    """
    Validate CSS selector syntax (basic check).

    Args:
        selector: CSS selector to validate.

    Returns:
        The selector if valid.

    Raises:
        ValidationError: If selector appears invalid.
    """
    if not selector:
        raise ValidationError("Selector cannot be empty", "selector")

    # Basic sanity checks
    if len(selector) > 500:
        raise ValidationError("Selector too long", "selector")

    # Check for obviously invalid patterns
    invalid_patterns = [
        r"^\s*$",  # Empty/whitespace only
        r"<[^>]+>",  # HTML tags like <div> or </p>
    ]
    for pattern in invalid_patterns:
        if re.search(pattern, selector):
            raise ValidationError(f"Invalid selector: {selector}", "selector")

    return selector


def validate_timeout(timeout: float) -> float:
    """
    Validate timeout value.

    Args:
        timeout: Timeout in seconds.

    Returns:
        Validated timeout.

    Raises:
        ValidationError: If timeout is invalid.
    """
    if timeout <= 0:
        raise ValidationError("Timeout must be positive", "timeout")
    if timeout > 300:
        raise ValidationError("Timeout cannot exceed 300 seconds", "timeout")
    return timeout
