"""
Scrape command for CiberWebScan CLI.

Handles web scraping operations - static and dynamic.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from ciberwebscan.cli.output import (
    format_scrape_result,
    format_service_result,
    print_error,
    print_header,
    print_info,
)
from ciberwebscan.cli.validators import (
    ValidationError,
    validate_format,
    validate_selector,
    validate_timeout,
    validate_url,
)
from ciberwebscan.config.loader import get_config

scrape = typer.Typer(
    name="scrape",
    help="Web scraping commands.",
    no_args_is_help=True,
)

try:
    _DEFAULT_SCRAPE_TIMEOUT = get_config().http.timeout.read
except Exception:
    _DEFAULT_SCRAPE_TIMEOUT = 30.0


@scrape.command("url")
def scrape_url(
    url: Annotated[str, typer.Argument(help="URL to scrape")],
    # Scraping mode
    dynamic: Annotated[
        bool,
        typer.Option("--dynamic", "-d", help="Use browser-based scraping"),
    ] = False,
    wait_for: Annotated[
        str | None,
        typer.Option(
            "--wait-for", "-w", help="CSS selector to wait for (dynamic mode)"
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Request timeout in seconds"),
    ] = _DEFAULT_SCRAPE_TIMEOUT,
    # Content extraction
    selector: Annotated[
        str | None,
        typer.Option("--selector", "-s", help="CSS selector to extract"),
    ] = None,
    attributes: Annotated[
        str | None,
        typer.Option(
            "--attributes", "-a", help="Attributes to extract (comma-separated)"
        ),
    ] = None,
    # Pagination
    pagination: Annotated[
        str | None,
        typer.Option("--pagination", "-p", help="Pagination selector"),
    ] = None,
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", help="Maximum pages to scrape"),
    ] = 1,
    # Export
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Export format: json, jsonl, csv"),
    ] = "json",
    # Output options
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Minimal output"),
    ] = False,
    # Network options
    user_agent: Annotated[
        str | None,
        typer.Option("--user-agent", "-ua", help="Custom User-Agent string"),
    ] = None,
    headers: Annotated[
        str | None,
        typer.Option(
            "--headers",
            "-H",
            help="Custom headers (format: 'Key: Value, Key2: Value2')",
        ),
    ] = None,
    proxy: Annotated[
        str | None,
        typer.Option("--proxy", help="HTTP/HTTPS proxy URL"),
    ] = None,
    cookies: Annotated[
        str | None,
        typer.Option(
            "--cookies", "-c", help="Cookies (format: 'name1=value1; name2=value2')"
        ),
    ] = None,
    check_robots: Annotated[
        bool,
        typer.Option(
            "--check-robots/--no-check-robots", "-cr", help="Respect robots.txt"
        ),
    ] = True,
    # Structured extraction
    extract_schema: Annotated[
        str | None,
        typer.Option(
            "--extract-schema",
            "-es",
            help="JSON extraction schema (string or file path)",
        ),
    ] = None,
) -> None:
    """
    Scrape a single URL.

    Examples:

        # Simple scrape
        ciberwebscan scrape url https://example.com

        # Extract specific elements
        ciberwebscan scrape url https://example.com -s "div.product" -a "href,title"

        # Dynamic scraping with browser
        ciberwebscan scrape url https://spa-app.com -d --wait-for ".content"

        # Export results
        ciberwebscan scrape url https://example.com -s "a" -o links.json
    """
    try:
        # Validate inputs
        validated_url = validate_url(url)
        validate_timeout(timeout)
        if selector:
            validate_selector(selector)
        if output:
            validate_format(format)

        # Parse headers if provided
        headers_dict: dict[str, str] = {}
        if headers:
            for pair in headers.split(","):
                if ":" in pair:
                    key, value = pair.split(":", 1)
                    headers_dict[key.strip()] = value.strip()

        # Parse cookies if provided
        cookies_dict: dict[str, str] = {}
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    cookies_dict[key.strip()] = value.strip()

        # Parse extract schema if provided
        schema_dict: dict | None = None
        if extract_schema:
            import json
            from pathlib import Path

            schema_path = Path(extract_schema)
            if schema_path.exists():
                schema_dict = json.loads(schema_path.read_text())
            else:
                schema_dict = json.loads(extract_schema)

        # Build options
        from ciberwebscan.services import ScrapeOptions, ScrapeService

        attrs = attributes.split(",") if attributes else []

        options = ScrapeOptions(
            url=validated_url,
            dynamic=dynamic,
            wait_for=wait_for,
            timeout=timeout,
            selector=selector,
            attributes=attrs,
            pagination_selector=pagination,
            pagination_limit=max_pages,
            export=output,
            export_format=format,
            headers=headers_dict,
            cookies=cookies_dict,
            proxy=proxy,
            user_agent=user_agent,
            check_robots=check_robots,
            schema=schema_dict,
        )

        if not quiet:
            print_info(f"Scraping: {validated_url}")
            if dynamic:
                print_info("Mode: Dynamic (browser)")

        # Execute
        service = ScrapeService()
        result = service.scrape(options)

        # Output
        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success:
                format_scrape_result(result.data)
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


@scrape.command("batch")
def scrape_batch(
    urls: Annotated[
        list[str],
        typer.Argument(help="URLs to scrape"),
    ],
    # Options
    selector: Annotated[
        str | None,
        typer.Option("--selector", "-s", help="CSS selector to extract"),
    ] = None,
    dynamic: Annotated[
        bool,
        typer.Option("--dynamic", "-d", help="Use browser-based scraping"),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Request timeout in seconds"),
    ] = _DEFAULT_SCRAPE_TIMEOUT,
    # Export
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Export format"),
    ] = "jsonl",
    # Output options
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON"),
    ] = False,
) -> None:
    """
    Scrape multiple URLs.

    Examples:

        # Scrape multiple URLs
        ciberwebscan scrape batch https://example.com https://example.org

        # With selector and export
        ciberwebscan scrape batch url1 url2 url3 -s "h1" -o results.jsonl
    """
    try:
        if not urls:
            print_error("At least one URL is required")
            sys.exit(2)

        validated_urls = [validate_url(u) for u in urls]

        from ciberwebscan.services import ScrapeOptions, ScrapeService

        options = ScrapeOptions(
            url=validated_urls[0],  # Base options
            dynamic=dynamic,
            timeout=timeout,
            selector=selector,
            export=output,
            export_format=format,
        )

        print_info(f"Scraping {len(validated_urls)} URLs...")

        service = ScrapeService()
        result = service.scrape_multiple(validated_urls, options)

        if json_output:
            exit_code = format_service_result(result, json_output=True)
        else:
            if result.success and result.data:
                print_header(f"Results ({len(result.data)} successful)")
                for i, r in enumerate(result.data[:5], 1):
                    print_info(f"  [{i}] {r.url} - {r.status_code}")
                if len(result.data) > 5:
                    print_info(f"  ... and {len(result.data) - 5} more")
            exit_code = format_service_result(result, json_output=False)

        sys.exit(exit_code)

    except ValidationError as e:
        print_error(str(e))
        sys.exit(2)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
